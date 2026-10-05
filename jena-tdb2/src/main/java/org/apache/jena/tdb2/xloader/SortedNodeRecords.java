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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.*;

import org.apache.jena.atlas.lib.Bytes;
import org.apache.jena.atlas.lib.Hex;
import org.apache.jena.dboe.base.file.BinaryDataFile;
import org.apache.jena.dboe.base.record.Record;
import org.apache.jena.dboe.base.record.RecordFactory;
import org.apache.jena.riot.thrift.ThriftConvert;
import org.apache.jena.riot.thrift.wire.RDF_Term;
import org.apache.jena.tdb2.TDBException;
import org.apache.jena.tdb2.store.NodeId;
import org.apache.jena.tdb2.store.NodeIdFactory;
import org.apache.jena.tdb2.sys.SystemTDB;

/**
 * The node table records from the sorted node lines ({@code hash thrift}, both in hex,
 * one node per line), in stages:
 * <ol>
 * <li>A reader thread reads the input in blocks of about 1 MB, cut at line ends, and
 * numbers them.</li>
 * <li>{@code decoders} threads decode whole blocks: hex through a table, and a check of
 * each term with {@link ThriftConvert#termFromBytes}.</li>
 * <li>The thread iterating (the one packing the B+tree, in the write transaction) takes
 * the decoded blocks in their original order and appends each term to the object file;
 * its offset is the NodeId.</li>
 * </ol>
 * The records and the object file are the same as decoding one byte at a time, for any
 * number of decoders. Errors in the sorted input (a bad hex character, an incomplete
 * hash, a missing separator, an empty line, a term that is not valid Thrift) end the
 * iteration with an exception. {@link #close} stops the other threads if the iteration
 * ends early.
 */
final class SortedNodeRecords implements Iterator<Record>, AutoCloseable {

    private static final RecordFactory factory = new RecordFactory(SystemTDB.LenNodeHash, NodeId.SIZE);
    private static final int BlockSize = 1 << 20;

    private static final byte[] HEX = new byte[256];
    static {
        Arrays.fill(HEX, (byte)-1);
        for ( int i = 0 ; i < 10 ; i++ )
            HEX['0' + i] = (byte)i;
        for ( int i = 0 ; i < 6 ; i++ ) {
            HEX['A' + i] = (byte)(10 + i);
            HEX['a' + i] = (byte)(10 + i);
        }
    }

    private record Block(long seq, byte[] bytes, int length) {}
    private record Batch(byte[][] keys, byte[][] terms, int size) {}

    private static final Block END = new Block(-1, null, 0);

    private final BinaryDataFile objectFile;
    private final int decoders;
    // Blocks read but not yet taken by the iterating thread: bounds memory.
    private final Semaphore inFlight;
    private final BlockingQueue<Block> blocks;
    private final ConcurrentHashMap<Long, Batch> decoded = new ConcurrentHashMap<>();
    private final Object signal = new Object();
    private final List<Thread> threads = new ArrayList<>();
    private volatile Throwable failure = null;
    private volatile long blockCount = -1;      // Set by the reader at the end of the input.
    private volatile boolean closed = false;

    private long nextSeq = 0;
    private Batch batch = null;
    private int index = 0;
    private boolean ended = false;

    /** One decoder thread. */
    SortedNodeRecords(InputStream input, BinaryDataFile objectFile) {
        this(input, objectFile, 1);
    }

    SortedNodeRecords(InputStream input, BinaryDataFile objectFile, int decoders) {
        if ( decoders < 1 )
            throw new IllegalArgumentException("decoders: " + decoders);
        this.objectFile = objectFile;
        this.decoders = decoders;
        this.inFlight = new Semaphore(4 * decoders);
        this.blocks = new ArrayBlockingQueue<>(2 * decoders + 1);
        // Daemons: if the iteration is abandoned, they stop at their next block.
        threads.add(Thread.ofPlatform().name("tdb2-xloader-terms-read").daemon().start(() -> read(input)));
        for ( int i = 0 ; i < decoders ; i++ )
            threads.add(Thread.ofPlatform().name("tdb2-xloader-terms-decode-" + i).daemon().start(this::decode));
    }

    @Override
    public boolean hasNext() {
        if ( ended )
            return false;
        while ( batch == null || index == batch.size() ) {
            if ( batch != null ) {
                inFlight.release();
                batch = null;
            }
            Batch b = take();
            if ( b == null ) {
                ended = true;
                return false;
            }
            batch = b;
            index = 0;
        }
        return true;
    }

    /** The next decoded block in order, or null at the end of the input. */
    private Batch take() {
        synchronized (signal) {
            for ( ;; ) {
                Throwable th = failure;
                if ( th != null ) {
                    ended = true;
                    if ( th instanceof RuntimeException ex )
                        throw ex;
                    throw new TDBException("Failed to read sorted node records", th);
                }
                Batch b = decoded.remove(nextSeq);
                if ( b != null ) {
                    nextSeq++;
                    return b;
                }
                if ( blockCount >= 0 && nextSeq >= blockCount )
                    return null;
                try {
                    signal.wait(100);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    ended = true;
                    throw new TDBException("Interrupted reading sorted node records", ex);
                }
            }
        }
    }

    @Override
    public Record next() {
        if ( !hasNext() )
            throw new NoSuchElementException();
        byte[] key = batch.keys()[index];
        byte[] term = batch.terms()[index];
        index++;
        // The term's offset in the object file is its NodeId.
        long x = objectFile.length();
        NodeId nodeId = NodeIdFactory.createPtr(x);
        objectFile.write(term);
        byte[] bbNodeId = new byte[NodeId.SIZE];
        Bytes.setLong(nodeId.getPtrLocation(), bbNodeId);
        return factory.create(key, bbNodeId);
    }

    @Override
    public void close() {
        closed = true;
        threads.forEach(Thread::interrupt);
    }

    private void fail(Throwable th) {
        if ( failure == null )
            failure = th;
        synchronized (signal) {
            signal.notifyAll();
        }
    }

    // ---- Reader thread: blocks cut at line ends.

    private void read(InputStream input) {
        try {
            byte[] buf = new byte[BlockSize];
            int filled = 0;
            long seq = 0;
            for ( ;; ) {
                int n = input.read(buf, filled, buf.length - filled);
                if ( n < 0 ) {
                    if ( filled > 0 ) {
                        // A last line without a newline: as if it had one.
                        if ( filled == buf.length )
                            buf = Arrays.copyOf(buf, buf.length + 1);
                        buf[filled++] = '\n';
                        if ( !put(new Block(seq++, Arrays.copyOf(buf, filled), filled)) )
                            return;
                    }
                    blockCount = seq;
                    for ( int i = 0 ; i < decoders ; i++ )
                        putEnd();
                    synchronized (signal) {
                        signal.notifyAll();
                    }
                    return;
                }
                filled += n;
                int cut = lastNewline(buf, filled) + 1;
                if ( cut == 0 ) {
                    if ( filled == buf.length )
                        buf = Arrays.copyOf(buf, buf.length * 2);
                    continue;
                }
                if ( filled < buf.length / 2 && cut < filled )
                    continue;   // Read more before cutting a small block.
                if ( !put(new Block(seq++, Arrays.copyOf(buf, cut), cut)) )
                    return;
                System.arraycopy(buf, cut, buf, 0, filled - cut);
                filled -= cut;
            }
        } catch (IOException ex) {
            fail(new TDBException("Failed to read sorted node records", ex));
        } catch (Throwable th) {
            fail(th);
        }
    }

    private static int lastNewline(byte[] buf, int end) {
        for ( int i = end - 1 ; i >= 0 ; i-- )
            if ( buf[i] == '\n' )
                return i;
        return -1;
    }

    private boolean put(Block block) {
        try {
            while ( !inFlight.tryAcquire(100, TimeUnit.MILLISECONDS) ) {
                if ( closed || failure != null )
                    return false;
            }
            while ( !blocks.offer(block, 100, TimeUnit.MILLISECONDS) ) {
                if ( closed || failure != null )
                    return false;
            }
            return true;
        } catch (InterruptedException ex) {
            return false;
        }
    }

    private void putEnd() {
        try {
            while ( !blocks.offer(END, 100, TimeUnit.MILLISECONDS) ) {
                if ( closed || failure != null )
                    return;
            }
        } catch (InterruptedException ex) { /* Stopping */ }
    }

    // ---- Decoder threads

    private void decode() {
        RDF_Term term = new RDF_Term();
        byte[] thrift = new byte[256];
        try {
            for ( ;; ) {
                Block block = blocks.poll(100, TimeUnit.MILLISECONDS);
                if ( closed || failure != null )
                    return;
                if ( block == null )
                    continue;
                if ( block == END )
                    return;
                List<byte[]> keys = new ArrayList<>();
                List<byte[]> terms = new ArrayList<>();
                byte[] buf = block.bytes();
                int pos = 0;
                while ( pos < block.length() ) {
                    int eol = pos;
                    while ( buf[eol] != '\n' )
                        eol++;
                    int i = pos;
                    if ( eol == i )
                        throw new TDBException("Failed to read sorted node records: empty line");
                    if ( eol - i < 2 * SystemTDB.LenNodeHash )
                        throw new TDBException("Failed to read sorted node records: incomplete node hash from sort");
                    byte[] key = new byte[SystemTDB.LenNodeHash];
                    for ( int k = 0 ; k < key.length ; k++, i += 2 )
                        key[k] = (byte)((nibble(buf[i]) << 4) | nibble(buf[i + 1]));
                    if ( i == eol || buf[i] != ' ' )
                        throw new TDBException("Failed to read sorted node records: missing separator after node hash");
                    i++;
                    int len = 0;
                    for ( ; i < eol ; i += 2 ) {
                        if ( i + 1 == eol )
                            throw new TDBException("Failed to read sorted node records: odd number of hex digits");
                        if ( len == thrift.length )
                            thrift = Arrays.copyOf(thrift, thrift.length * 2);
                        thrift[len++] = (byte)((nibble(buf[i]) << 4) | nibble(buf[i + 1]));
                    }
                    byte[] t = Arrays.copyOf(thrift, len);
                    // Check the term can be read back.
                    ThriftConvert.termFromBytes(term, t);
                    keys.add(key);
                    terms.add(t);
                    pos = eol + 1;
                }
                Batch b = new Batch(keys.toArray(new byte[0][]), terms.toArray(new byte[0][]), keys.size());
                decoded.put(block.seq(), b);
                synchronized (signal) {
                    signal.notifyAll();
                }
            }
        } catch (InterruptedException ex) {
            // Stopping
        } catch (Throwable th) {
            fail(th);
        }
    }

    private static int nibble(byte b) {
        int v = HEX[b & 0xFF];
        // Hex.hexByteToInt throws for a bad character, with the usual message.
        return v >= 0 ? v : Hex.hexByteToInt(b & 0xFF);
    }
}
