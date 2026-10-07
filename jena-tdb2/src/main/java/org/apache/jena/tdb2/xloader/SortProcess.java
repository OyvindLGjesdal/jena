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

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.*;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.tdb2.TDBException;

/** Owns a sort subprocess and the workers using its pipes. */
final class SortProcess implements AutoCloseable {
    @FunctionalInterface
    interface Producer {
        void write(OutputStream output) throws IOException;
    }

    @FunctionalInterface
    interface Consumer<T> {
        // Call checkSuccess before committing changes made from the sorted input.
        T read(InputStream input, Runnable checkSuccess) throws IOException;
    }

    private final Process process;
    private volatile boolean cancelled;
    private Future<?> producerTask;
    private final ExecutorService workers = Executors.newFixedThreadPool(4,
            Thread.ofPlatform().name("tdb2-xloader-", 0).factory());

    SortProcess(List<String> command) {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.environment().put("LC_ALL", "C");
        try {
            process = builder.start();
        } catch (IOException ex) {
            workers.shutdown();
            throw new TDBException("Failed to start sort program: " + command.get(0), ex);
        }
    }

    <T> T run(Producer producer, Consumer<T> consumer) {
        CompletionService<Object> completed = new ExecutorCompletionService<>(workers);
        Future<Object> errors = completed.submit(() -> {
            // Keep diagnostics bounded, but drain all stderr so the child cannot block.
            try ( InputStream input = process.getErrorStream() ) {
                ByteArrayOutputStream message = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int length;
                boolean truncated = false;
                while ((length = input.read(buffer)) != -1) {
                    int keep = Math.min(length, 64 * 1024 - message.size());
                    message.write(buffer, 0, keep);
                    truncated |= keep < length;
                }
                return message.toString(StandardCharsets.UTF_8) + (truncated ? "\n[stderr truncated]" : "");
            }
        });
        Future<Object> produced = completed.submit(() -> {
            try ( OutputStream output = IO.ensureBuffered(process.getOutputStream()) ) {
                producer.write(output);
            }
            return null;
        });
        producerTask = produced;
        Future<Object> sorted = completed.submit(() -> {
            int rc = process.waitFor();
            String message = (String)await(errors);
            if ( rc != 0 )
                throw new TDBException("Sort RC = " + rc + " : " + message);
            if ( !message.isBlank() )
                BulkLoaderX.LOG_Index.warn("Sort stderr: {}", message);
            return null;
        });
        Future<Object> consumed = completed.submit(() -> {
            try ( InputStream input = cancellableInput() ) {
                return consumer.read(input, () -> {
                    checkCancelled();
                    await(produced);
                    await(sorted);
                    checkCancelled();
                });
            }
        });
        // Observe failures in completion order, including when another worker is
        // blocked on a pipe, but report sort's own failure if it has one.
        // close() kills the child before joining the workers.
        for ( int i = 0; i < 4; i++ ) {
            try {
                await(completed.take());
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new TDBException("Interrupted while running sort", ex);
            } catch (RuntimeException ex) {
                throw sortFailureOr(ex, sorted);
            }
        }
        @SuppressWarnings("unchecked")
        T result = (T)await(consumed);
        return result;
    }

    /**
     * The failure to report: sort's own failure, with {@code failure} suppressed, if
     * sort has failed too. When sort exits with an error (for example, rejecting an
     * option), the producer sees a broken pipe, which can complete before sort's exit
     * code and stderr are read.
     */
    private RuntimeException sortFailureOr(RuntimeException failure, Future<Object> sorted) {
        if ( cancelled )
            return failure;
        try {
            // If sort caused the failure, it has exited or is exiting. If it is still
            // running, the failure is elsewhere: close() stops it.
            if ( !process.waitFor(SortExitWaitMillis, TimeUnit.MILLISECONDS) || process.exitValue() == 0 )
                return failure;
            sorted.get(SortExitWaitMillis, TimeUnit.MILLISECONDS);
        } catch (ExecutionException ex) {
            if ( ex.getCause() instanceof RuntimeException sortFailure && sortFailure != failure ) {
                sortFailure.addSuppressed(failure);
                return sortFailure;
            }
        } catch (TimeoutException ex) {
            // stderr is still open: report the failure as seen.
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
        return failure;
    }

    /** How long a failed pipeline waits for sort's exit code and stderr. */
    private static final long SortExitWaitMillis = 1000;

    /** True once {@link #close()} has started stopping the pipeline. */
    boolean isCancelled() {
        return cancelled;
    }

    private void checkCancelled() {
        if ( cancelled )
            throw new TDBException("Sort cancelled");
    }

    private InputStream cancellableInput() {
        // Check outside the buffer so cancellation also stops buffered records.
        return new FilterInputStream(IO.ensureBuffered(process.getInputStream())) {
            @Override
            public int read() throws IOException {
                checkCancelled();
                int value = in.read();
                checkCancelled();
                return value;
            }

            @Override
            public int read(byte[] bytes, int offset, int length) throws IOException {
                checkCancelled();
                int count = in.read(bytes, offset, length);
                checkCancelled();
                return count;
            }
        };
    }

    private static Object await(Future<?> future) {
        try {
            return future.get();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new TDBException("Interrupted while running sort", ex);
        } catch (ExecutionException ex) {
            Throwable cause = ex.getCause();
            if ( cause instanceof RuntimeException runtime )
                throw runtime;
            if ( cause instanceof Error error )
                throw error;
            throw new TDBException("Sort pipeline failed", cause);
        }
    }

    @Override
    public void close() {
        cancelled = true;
        // Kill before closing pipes: closing a pipe while another thread is
        // blocked writing to it can itself block. Include gzip/sort descendants.
        // Still clean up the direct child if descendant inspection is denied.
        try ( BulkLoaderX.Cleanup cleanup = this::closeProcess ) {
            if ( process.isAlive() )
                process.descendants().forEach(ProcessHandle::destroyForcibly);
        }
    }

    private void closeProcess() {
        if ( process.isAlive() )
            process.destroyForcibly();
        // Only the producer may be interrupted. The consumer owns a database
        // transaction: interrupting its file I/O can also break rollback and
        // leave the writer lock held. Killing sort unblocks the pipe readers;
        // cancellation checks let the consumer abort on its own thread.
        if ( producerTask != null )
            producerTask.cancel(true);
        workers.shutdown();
        boolean interrupted = Thread.interrupted();
        try {
            for (;;) {
                try {
                    process.waitFor();
                    if ( workers.awaitTermination(1, TimeUnit.SECONDS) )
                        break;
                } catch (InterruptedException ex) {
                    interrupted = true;
                }
            }
            // Try all closes and preserve close failures with suppressed exceptions.
            try ( OutputStream output = process.getOutputStream();
                  InputStream input = process.getInputStream();
                  InputStream error = process.getErrorStream() ) {}
            catch (IOException ex) { throw new TDBException("Failed to close sort pipes", ex); }
        } finally {
            if ( interrupted )
                Thread.currentThread().interrupt();
        }
    }
}
