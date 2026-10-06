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

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.tdb2.TDBException;

/**
 * One reader of a workfile for several sorts at the same time (indexes built in
 * parallel): the file is decompressed once, on one thread, and each block goes to every
 * sort. Each sort has its own queue and writes it to its stdin on its own thread (its
 * {@link #producer()}), so a sort that stops reading for a while (to sort a buffer) holds
 * up the others only when the reader is {@link #QueueBlocks} blocks ahead of it.
 * <p>
 * If one sort's input fails or is cancelled, the reader stops and the other sorts'
 * inputs fail as well, so no index is committed from part of the workfile. (The other
 * builds are cancelled anyway when one fails.) Every sort must take its producer and run
 * it: the reader waits for the slowest queue.
 */
final class SharedWorkfileReader implements AutoCloseable {

    /** Bytes in a block: small enough not to be a humongous object for G1 with a small heap. */
    private static final int BlockSize = 256 * 1024;

    /** Blocks queued for each sort: how far the reader may get ahead of the slowest sort (64 MB). */
    private static final int QueueBlocks = 256;

    private record Block(byte[] bytes, int length) {}

    private static final Block END = new Block(new byte[0], 0);

    private final String datafile;
    private final int blockSize;
    private final List<BlockingQueue<Block>> queues = new ArrayList<>();
    private final AtomicInteger taken = new AtomicInteger();
    private final AtomicReference<Throwable> failure = new AtomicReference<>();
    private volatile boolean closed = false;
    private final Thread reader;

    /** Start reading {@code datafile} (decompressing it as {@link IO#openFile} does) for {@code sorts} sorts. */
    SharedWorkfileReader(String datafile, int sorts) {
        this(datafile, sorts, BlockSize, QueueBlocks);
    }

    /** With a given block size and queue length (for tests). */
    SharedWorkfileReader(String datafile, int sorts, int blockSize, int queueBlocks) {
        this.datafile = datafile;
        this.blockSize = blockSize;
        for ( int i = 0 ; i < sorts ; i++ )
            queues.add(new ArrayBlockingQueue<>(queueBlocks));
        // Daemon: close() stops and joins it.
        reader = Thread.ofPlatform().name("tdb2-xloader-workfile-read").daemon().start(this::read);
    }

    /** The input of one sort: writes the whole workfile to the sort's stdin. Once per sort. */
    SortProcess.Producer producer() {
        int i = taken.getAndIncrement();
        if ( i >= queues.size() )
            throw new IllegalStateException("More than " + queues.size() + " sorts reading " + datafile);
        BlockingQueue<Block> queue = queues.get(i);
        return output -> {
            try {
                for ( ;; ) {
                    Block block = take(queue);
                    if ( block == END )
                        return;
                    output.write(block.bytes(), 0, block.length());
                }
            } catch (Throwable th) {
                // Stop the reader and the other sorts' inputs.
                fail(th);
                throw th;
            }
        };
    }

    private void read() {
        try ( InputStream input = IO.openFile(datafile) ) {
            for ( ;; ) {
                byte[] bytes = new byte[blockSize];
                int n = input.readNBytes(bytes, 0, blockSize);
                if ( n > 0 && !putAll(new Block(bytes, n)) )
                    return;
                if ( n < blockSize )
                    break;
            }
            putAll(END);
        } catch (Throwable th) {
            fail(th);
        }
    }

    /** Put a block in every queue, unless the reading has failed or is closed. */
    private boolean putAll(Block block) throws InterruptedException {
        for ( BlockingQueue<Block> queue : queues ) {
            while ( !queue.offer(block, 100, TimeUnit.MILLISECONDS) ) {
                if ( failure.get() != null || closed )
                    return false;
            }
        }
        return true;
    }

    private Block take(BlockingQueue<Block> queue) {
        try {
            for ( ;; ) {
                Throwable th = failure.get();
                if ( th != null )
                    throw new TDBException("Reading " + datafile + " for the sorts failed", th);
                Block block = queue.poll(100, TimeUnit.MILLISECONDS);
                if ( block != null )
                    return block;
                if ( closed )
                    throw new TDBException("Reading " + datafile + " for the sorts was stopped");
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new TDBException("Interrupted reading " + datafile + " for the sorts", ex);
        }
    }

    private void fail(Throwable th) {
        failure.compareAndSet(null, th);
    }

    /** Stop the reader, if it is still running, and wait for it. */
    @Override
    public void close() {
        closed = true;
        reader.interrupt();
        boolean interrupted = false;
        for ( ;; ) {
            try {
                reader.join();
                break;
            } catch (InterruptedException ex) {
                interrupted = true;
            }
        }
        if ( interrupted )
            Thread.currentThread().interrupt();
    }
}
