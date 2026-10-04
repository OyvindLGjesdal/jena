/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 *   SPDX-License-Identifier: Apache-2.0
 */
package org.apache.jena.tdb2.xloader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.BooleanSupplier;
import java.util.function.LongConsumer;
import java.util.function.Supplier;

import org.apache.jena.graph.Triple;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.riot.RiotParseException;
import org.apache.jena.riot.lang.LabelToNode;
import org.apache.jena.riot.system.ErrorHandler;
import org.apache.jena.riot.system.ErrorHandlerFactory;
import org.apache.jena.riot.system.StreamRDF;
import org.apache.jena.riot.system.StreamRDFWrapper;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.tdb2.TDBException;

/**
 * Parse N-Triples or N-Quads input on several threads, for the node table and ingest
 * steps.
 * <p>
 * A reader thread cuts the decompressed input into chunks at line ends; worker threads
 * parse each chunk with RIOT's parser for the language, so every statement is parsed as
 * it would be in one pass (one statement per line). Each worker sends a chunk's
 * statements to its own {@link Worker}, which writes its results when the chunk ends.
 * The calling thread waits and, if given an {@link Owner}, serves requests from the
 * workers meanwhile (ingest: allocating nodes in the calling thread's write transaction).
 * <p>
 * Blank node labels: every chunk uses a label policy with the file's seed
 * ({@link LabelToNode#createScopeByDocumentHash(UUID)}), so a label is the same blank
 * node in every chunk. Parse errors report the line in the whole input; warnings report
 * the line within the chunk and the chunk's byte offset.
 */
final class ParallelParser {

    /** The per-thread consumer of parsed statements. Created and used on its worker thread. */
    interface Worker {
        /** Receives the statements of each chunk. */
        StreamRDF stream();
        /** Called after each chunk: write the chunk's results. */
        void endChunk() throws IOException;
        /** Called once when the worker stops, also after a failure. */
        default void close() {}
    }

    /** Work for the calling thread while the workers run. */
    interface Owner {
        /** Handle pending requests, waiting up to {@code millis} for one. */
        void serve(long millis) throws InterruptedException;
    }

    private record Chunk(long seq, long offset, byte[] bytes, int length) {}

    private static final Chunk END = new Chunk(-1, -1, new byte[0], 0);

    private ParallelParser() {}

    /**
     * Parse all of {@code input} (decompressed N-Triples or N-Quads).
     * @param seed      blank node label seed for this file (see {@link BlankNodeSeed})
     * @param progress  called with the number of triples or quads in each parsed chunk
     * @param workers   creates the consumer for each worker thread, on that thread
     * @param owner     work for the calling thread, or null to just wait
     * @return the number of triples or quads
     */
    static long parse(InputStream input, Lang lang, String baseIRI, UUID seed,
                      int threads, int chunkSize, BooleanSupplier cancelled, LongConsumer progress,
                      Supplier<Worker> workers, Owner owner) {
        // Enough queued chunks to keep the workers busy, without holding a chunk per
        // worker in the queue when there are many workers (each chunk is ChunkSize bytes).
        BlockingQueue<Chunk> queue = new ArrayBlockingQueue<>(Math.min(2 * threads, threads + 16));
        Map<Long, Long> chunkLines = new ConcurrentHashMap<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        LongAdder count = new LongAdder();
        CountDownLatch finished = new CountDownLatch(threads);
        ExecutorService pool = Executors.newFixedThreadPool(threads,
                Thread.ofPlatform().name("tdb2-xloader-parse-", 0).factory());
        Thread reader = null;
        try {
            for ( int i = 0 ; i < threads ; i++ ) {
                pool.submit(() -> {
                    try {
                        work(queue, lang, baseIRI, seed, workers, cancelled, progress, chunkLines, count);
                    } catch (Throwable th) {
                        failure.compareAndSet(null, th);
                    } finally {
                        finished.countDown();
                    }
                    return null;
                });
            }
            // Daemon: after a failure it is not waited for; it stops at its next read.
            reader = Thread.ofPlatform().name("tdb2-xloader-read").daemon().start(() -> {
                read(input, chunkSize, queue, failure, cancelled);
                if ( failure.get() == null ) {
                    // Normal end: each worker stops at an END marker.
                    for ( int i = 0 ; i < threads ; i++ )
                        putUnlessFailed(queue, END, failure);
                }
            });
            try {
                while ( !finished.await(0, TimeUnit.MILLISECONDS) && failure.get() == null ) {
                    if ( owner != null )
                        owner.serve(10);
                    else
                        finished.await(50, TimeUnit.MILLISECONDS);
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                failure.compareAndSet(null, new TDBException("Parsing interrupted", ex));
            } catch (RuntimeException | Error ex) {
                failure.compareAndSet(null, ex);
            }
            if ( failure.get() == null )
                join(reader);
            if ( failure.get() == null && cancelled.getAsBoolean() )
                throw new TDBException("Parsing interrupted");
        } finally {
            // Interrupts workers waiting for chunks or for the owner, after a failure.
            pool.shutdownNow();
            awaitTermination(pool);
        }
        Throwable th = failure.get();
        if ( th != null )
            throw rethrow(th, queue, chunkLines);
        return count.sum();
    }

    /** Read the input and queue chunks that end at a line end. */
    private static void read(InputStream input, int chunkSize, BlockingQueue<Chunk> queue,
                             AtomicReference<Throwable> failure, BooleanSupplier cancelled) {
        byte[] buf = new byte[chunkSize];
        int filled = 0;
        long offset = 0;
        long seq = 0;
        try {
            for ( ;; ) {
                if ( failure.get() != null || cancelled.getAsBoolean() )
                    return;
                int n = input.readNBytes(buf, filled, buf.length - filled);
                filled += n;
                if ( filled < buf.length ) {
                    // End of input: the rest, which may not end with a newline.
                    if ( filled > 0 )
                        putUnlessFailed(queue, new Chunk(seq++, offset, Arrays.copyOf(buf, filled), filled), failure);
                    return;
                }
                int cut = lastNewline(buf, filled) + 1;
                if ( cut == 0 ) {
                    // A line longer than the buffer: read more of it.
                    buf = Arrays.copyOf(buf, buf.length * 2);
                    continue;
                }
                if ( !putUnlessFailed(queue, new Chunk(seq++, offset, Arrays.copyOf(buf, cut), cut), failure) )
                    return;
                offset += cut;
                System.arraycopy(buf, cut, buf, 0, filled - cut);
                filled -= cut;
            }
        } catch (IOException ex) {
            failure.compareAndSet(null, new TDBException("Failed to read input", ex));
        } catch (Throwable th) {
            failure.compareAndSet(null, th);
        }
    }

    private static int lastNewline(byte[] buf, int end) {
        for ( int i = end - 1 ; i >= 0 ; i-- )
            if ( buf[i] == '\n' )
                return i;
        return -1;
    }

    private static boolean putUnlessFailed(BlockingQueue<Chunk> queue, Chunk chunk, AtomicReference<Throwable> failure) {
        try {
            while ( !queue.offer(chunk, 100, TimeUnit.MILLISECONDS) ) {
                if ( failure.get() != null )
                    return false;
            }
            return true;
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            failure.compareAndSet(null, new TDBException("Parsing interrupted", ex));
            return false;
        }
    }

    private static void work(BlockingQueue<Chunk> queue, Lang lang, String baseIRI, UUID seed,
                             Supplier<Worker> workers, BooleanSupplier cancelled, LongConsumer progress,
                             Map<Long, Long> chunkLines, LongAdder count) throws IOException, InterruptedException {
        Worker worker = workers.get();
        try {
            long[] statements = new long[1];
            StreamRDF counting = new StreamRDFWrapper(worker.stream()) {
                @Override public void triple(Triple triple) { statements[0]++; super.triple(triple); }
                @Override public void quad(Quad quad)       { statements[0]++; super.quad(quad); }
            };
            for ( ;; ) {
                Chunk chunk = queue.take();
                if ( chunk == END )
                    return;
                if ( cancelled.getAsBoolean() || Thread.currentThread().isInterrupted() )
                    throw new TDBException("Parsing interrupted");
                chunkLines.put(chunk.seq(), lines(chunk));
                statements[0] = 0;
                try {
                    RDFParser.source(new ByteArrayInputStream(chunk.bytes(), 0, chunk.length()))
                            .forceLang(lang)
                            .base(baseIRI)
                            .labelToNode(LabelToNode.createScopeByDocumentHash(seed))
                            .errorHandler(chunkErrorHandler(chunk.offset()))
                            .parse(counting);
                } catch (RiotParseException ex) {
                    throw new ChunkParseException(chunk.seq(), ex);
                }
                worker.endChunk();
                count.add(statements[0]);
                progress.accept(statements[0]);
            }
        } finally {
            worker.close();
        }
    }

    private static long lines(Chunk chunk) {
        long n = 0;
        byte[] b = chunk.bytes();
        for ( int i = 0 ; i < chunk.length() ; i++ )
            if ( b[i] == '\n' )
                n++;
        return n;
    }

    /**
     * Warnings are logged with the chunk's position added (the line is within the chunk).
     * Errors stop the parse, as with the default handler; the exception is given the line
     * in the whole input before it is thrown from {@link #parse}.
     */
    private static ErrorHandler chunkErrorHandler(long offset) {
        ErrorHandler base = ErrorHandlerFactory.getDefaultErrorHandler();
        String where = " (line within the chunk at byte offset " + offset + " of the input)";
        return new ErrorHandler() {
            @Override public void warning(String message, long line, long col) { base.warning(message + where, line, col); }
            @Override public void error(String message, long line, long col)   { throw new RiotParseException(message, line, col); }
            @Override public void fatal(String message, long line, long col)   { throw new RiotParseException(message, line, col); }
        };
    }

    /** A parse error in a chunk; turned into one with the line in the whole input. */
    private static final class ChunkParseException extends RuntimeException {
        final long seq;
        ChunkParseException(long seq, RiotParseException cause) {
            super(cause);
            this.seq = seq;
        }
    }

    private static RuntimeException rethrow(Throwable th, BlockingQueue<Chunk> queue, Map<Long, Long> chunkLines) {
        if ( th instanceof ChunkParseException chunkEx ) {
            RiotParseException ex = (RiotParseException)chunkEx.getCause();
            // Chunks still queued were counted by no worker.
            for ( Chunk chunk : queue )
                if ( chunk != END )
                    chunkLines.putIfAbsent(chunk.seq(), lines(chunk));
            long before = 0;
            for ( long s = 0 ; s < chunkEx.seq ; s++ ) {
                Long n = chunkLines.get(s);
                if ( n == null )
                    return ex;  // Not known: keep the line within the chunk.
                before += n;
            }
            return new RiotParseException(ex.getOriginalMessage(), before + ex.getLine(), ex.getCol());
        }
        if ( th instanceof RuntimeException runtime )
            return runtime;
        if ( th instanceof Error error )
            throw error;
        return new TDBException("Parallel parsing failed", th);
    }

    private static void join(Thread thread) {
        boolean interrupted = Thread.interrupted();
        try {
            for ( ;; ) {
                try {
                    thread.join();
                    return;
                } catch (InterruptedException ex) {
                    interrupted = true;
                }
            }
        } finally {
            if ( interrupted )
                Thread.currentThread().interrupt();
        }
    }

    private static void awaitTermination(ExecutorService executor) {
        boolean interrupted = Thread.interrupted();
        try {
            for ( ;; ) {
                try {
                    if ( executor.awaitTermination(1, TimeUnit.SECONDS) )
                        return;
                } catch (InterruptedException ex) {
                    interrupted = true;
                }
            }
        } finally {
            if ( interrupted )
                Thread.currentThread().interrupt();
        }
    }
}
