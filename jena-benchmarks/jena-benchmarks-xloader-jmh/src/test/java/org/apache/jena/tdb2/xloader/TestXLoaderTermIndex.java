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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.junit.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.slf4j.LoggerFactory;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.atlas.lib.Bytes;
import org.apache.jena.atlas.lib.FileOps;
import org.apache.jena.dboe.base.file.BinaryDataFile;
import org.apache.jena.dboe.base.file.FileFactory;
import org.apache.jena.dboe.base.file.FileSet;
import org.apache.jena.dboe.base.file.Location;
import org.apache.jena.dboe.base.record.Record;
import org.apache.jena.dboe.base.record.RecordFactory;
import org.apache.jena.riot.system.AsyncParser;
import org.apache.jena.riot.thrift.ThriftConvert;
import org.apache.jena.riot.thrift.wire.RDF_Term;
import org.apache.jena.tdb2.store.NodeId;
import org.apache.jena.tdb2.store.NodeIdFactory;
import org.apache.jena.tdb2.sys.SystemTDB;

/**
 * The term index step of the node table stage: reading the sorted node lines
 * ({@code hash thrift}, both in hex), appending each term to the object file and
 * making the node table B+tree record (hash to NodeId). Building the B+tree from the
 * records is the same for every variant and not included.
 * <p>
 * Setup makes the sorted node lines for the file named by {@code XLOADER_JMH_DATA}, as a
 * load does ({@link ProcBuildNodeTableX.NodeHashTmpStream}, then {@code sort -u} on the
 * hash, with {@code LC_ALL=C}; {@code XLOADER_JMH_SORT} for the sort program), and checks
 * that every variant gives the same records and object file as {@code before}.
 * <ul>
 * <li>{@code before}: a copy of the previous reader, decoding one byte at a time, on a
 * stream that checks for cancellation on every read, as {@code SortProcess} does.</li>
 * <li>{@code pipeline}: the load's reader ({@code ProcBuildNodeTableX.records},
 * {@link SortedNodeRecords}): block reads and table hex decoding with the Thrift check on
 * a reader thread; object file writes on the calling thread.</li>
 * <li>{@code pipeline2}, {@code pipeline4}: the same with 2 or 4 decoder threads
 * ({@code --term-threads}).</li>
 * <li>{@code bulk}: the same decoding on one thread.</li>
 * <li>{@code bulkNoCheck}: the same without the Thrift check.</li>
 * </ul>
 */
@State(Scope.Benchmark)
public class TestXLoaderTermIndex {

    private static final RecordFactory factory = new RecordFactory(SystemTDB.LenNodeHash, NodeId.SIZE);

    private Path work;
    private Path sorted;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        String datafile = XLoaderJmh.dataFile();
        String tmp = System.getenv("XLOADER_JMH_TMP");
        Path tmpDir = ( tmp == null || tmp.isBlank() ) ? Path.of(System.getProperty("java.io.tmpdir")) : Path.of(tmp);
        work = Files.createTempDirectory(tmpDir, "xloader-jmh-terms");
        Path unsorted = work.resolve("nodes-unsorted.txt");
        try ( OutputStream out = IO.ensureBuffered(Files.newOutputStream(unsorted)) ) {
            var stream = new ProcBuildNodeTableX.NodeHashTmpStream(out);
            AsyncParser.asyncParse(datafile, stream);
            stream.finish();
        }
        sorted = work.resolve("nodes-sorted.txt");
        String sort = System.getenv("XLOADER_JMH_SORT");
        ProcessBuilder pb = new ProcessBuilder(List.of(sort == null || sort.isBlank() ? "sort" : sort,
                "--unique", "--key=1,1", "--buffer-size=25%", "--parallel=4",
                "--temporary-directory=" + work, "--output=" + sorted, unsorted.toString()));
        pb.environment().put("LC_ALL", "C");
        pb.inheritIO();
        if ( pb.start().waitFor() != 0 )
            throw new IllegalStateException("sort failed");
        Files.delete(unsorted);
        String expected = run(Variant.before);
        for ( Variant v : Variant.values() ) {
            String actual = run(v);
            if ( !expected.equals(actual) )
                throw new IllegalStateException(v + " differs from before: " + actual + " / " + expected);
        }
        System.out.printf("%n# sorted node lines: %,d bytes; %s%n", Files.size(sorted), expected);
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        FileOps.clearAll(work.toString());
        work.toFile().delete();
    }

    enum Variant { before, pipeline, pipeline2, pipeline4, bulk, bulkNoCheck }

    @Benchmark public String before() throws Exception      { return run(Variant.before); }
    @Benchmark public String pipeline() throws Exception    { return run(Variant.pipeline); }
    @Benchmark public String pipeline2() throws Exception   { return run(Variant.pipeline2); }
    @Benchmark public String pipeline4() throws Exception   { return run(Variant.pipeline4); }
    @Benchmark public String bulk() throws Exception        { return run(Variant.bulk); }
    @Benchmark public String bulkNoCheck() throws Exception { return run(Variant.bulkNoCheck); }

    /** Read all sorted lines with a variant; @return records, object file length and a digest of the records. */
    private String run(Variant v) throws Exception {
        Path objDir = Files.createTempDirectory(work, "obj");
        BinaryDataFile objectFile =
                FileFactory.createBinaryDataFile(new FileSet(Location.create(objDir.toString()), "nodes-data"), "obj");
        objectFile.open();
        MessageDigest md = MessageDigest.getInstance("MD5");
        long count = 0;
        try ( InputStream file = Files.newInputStream(sorted) ) {
            Iterator<Record> records = switch (v) {
                case before -> new ByteByByteRecords(cancellable(file), objectFile);
                case pipeline -> new SortedNodeRecords(cancellable(file), objectFile, 1);
                case pipeline2 -> new SortedNodeRecords(cancellable(file), objectFile, 2);
                case pipeline4 -> new SortedNodeRecords(cancellable(file), objectFile, 4);
                case bulk -> new BulkRecords(file, objectFile, true);
                case bulkNoCheck -> new BulkRecords(file, objectFile, false);
            };
            try {
                while ( records.hasNext() ) {
                    Record r = records.next();
                    md.update(r.getKey());
                    md.update(r.getValue());
                    count++;
                }
            } finally {
                if ( records instanceof AutoCloseable c )
                    c.close();
            }
            objectFile.sync();
            long length = objectFile.length();
            return String.format("records %,d, object file %,d bytes, digest %s", count, length,
                                 Bytes.asHex(Arrays.copyOf(md.digest(), 8)));
        } finally {
            objectFile.close();
            FileOps.clearAll(objDir.toString());
            objDir.toFile().delete();
        }
    }

    // As SortProcess.cancellableInput: a check before and after every read.
    private volatile boolean cancelled = false;

    private InputStream cancellable(InputStream in) {
        return new FilterInputStream(IO.ensureBuffered(in)) {
            @Override public int read() throws IOException {
                if ( cancelled ) throw new IOException("cancelled");
                int b = in.read();
                if ( cancelled ) throw new IOException("cancelled");
                return b;
            }
            @Override public int read(byte[] bytes, int off, int len) throws IOException {
                if ( cancelled ) throw new IOException("cancelled");
                int n = in.read(bytes, off, len);
                if ( cancelled ) throw new IOException("cancelled");
                return n;
            }
        };
    }

    /** The previous reader (before {@link SortedNodeRecords}): one byte at a time through {@code hexRead}. */
    private static final class ByteByByteRecords extends org.apache.jena.atlas.iterator.IteratorSlotted<Record> {
        private final byte[] bHash = new byte[SystemTDB.LenNodeHash];
        private final byte[] bbNodeId = new byte[NodeId.SIZE];
        private final RDF_Term term = new RDF_Term();
        private final InputStream input;
        private final BinaryDataFile objectFile;

        ByteByByteRecords(InputStream input, BinaryDataFile objectFile) {
            this.input = input;
            this.objectFile = objectFile;
        }

        @Override protected boolean hasMore() { return true; }

        @Override
        protected Record moveToNext() {
            try {
                for ( int i = 0 ; i < 16 ; i++ ) {
                    int x = ProcBuildNodeTableX.hexRead(input);
                    if ( x < 0 ) {
                        if ( i == 0 )
                            return null;
                        throw new IOException("Incomplete node hash from sort");
                    }
                    bHash[i] = (byte)(x & 0xFF);
                }
                if ( input.read() != ' ' )
                    throw new IOException("Missing separator after node hash");
                ByteArrayOutputStream bout = new ByteArrayOutputStream();
                for ( ;; ) {
                    int v = ProcBuildNodeTableX.hexRead(input);
                    if ( v < 0 )
                        break;
                    bout.write(v);
                }
                byte[] thrift = bout.toByteArray();
                ThriftConvert.termFromBytes(term, thrift);
                long x = objectFile.length();
                NodeId nodeId = NodeIdFactory.createPtr(x);
                objectFile.write(thrift);
                Bytes.setLong(nodeId.getPtrLocation(), bbNodeId);
                return factory.create(bHash, bbNodeId);
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        }
    }

    /** Prototype: block reads and table-driven hex decoding on one thread; same records and object file. */
    private static final class BulkRecords implements Iterator<Record> {
        private static final byte[] HEX = new byte[256];
        static {
            Arrays.fill(HEX, (byte)-1);
            for ( int i = 0 ; i < 10 ; i++ ) HEX['0' + i] = (byte)i;
            for ( int i = 0 ; i < 6 ; i++ ) { HEX['A' + i] = (byte)(10 + i); HEX['a' + i] = (byte)(10 + i); }
        }

        private final InputStream in;
        private final BinaryDataFile objectFile;
        private final boolean check;
        private final RDF_Term term = new RDF_Term();
        private byte[] buf = new byte[1 << 20];
        private int pos = 0;
        private int end = 0;
        private byte[] thrift = new byte[256];
        private Record next = null;

        BulkRecords(InputStream in, BinaryDataFile objectFile, boolean check) {
            this.in = in;
            this.objectFile = objectFile;
            this.check = check;
        }

        @Override
        public boolean hasNext() {
            if ( next == null )
                next = readRecord();
            return next != null;
        }

        @Override
        public Record next() {
            if ( !hasNext() )
                throw new java.util.NoSuchElementException();
            Record r = next;
            next = null;
            return r;
        }

        /** Make at least one complete line available from pos; false at end of input. */
        private boolean line() {
            for ( ;; ) {
                for ( int i = pos ; i < end ; i++ )
                    if ( buf[i] == '\n' )
                        return true;
                if ( pos > 0 ) {
                    System.arraycopy(buf, pos, buf, 0, end - pos);
                    end -= pos;
                    pos = 0;
                }
                if ( end == buf.length )
                    buf = Arrays.copyOf(buf, buf.length * 2);
                int n;
                try { n = in.read(buf, end, buf.length - end); }
                catch (IOException ex) { throw new UncheckedIOException(ex); }
                if ( n <= 0 ) {
                    if ( end > pos )
                        throw new IllegalStateException("Last sorted node line has no newline");
                    return false;
                }
                end += n;
            }
        }

        private Record readRecord() {
            if ( !line() )
                return null;
            byte[] key = new byte[SystemTDB.LenNodeHash];
            int i = pos;
            for ( int k = 0 ; k < key.length ; k++, i += 2 )
                key[k] = (byte)((nibble(buf[i]) << 4) | nibble(buf[i + 1]));
            if ( buf[i++] != ' ' )
                throw new IllegalStateException("Missing separator after node hash");
            int len = 0;
            while ( buf[i] != '\n' ) {
                if ( len == thrift.length )
                    thrift = Arrays.copyOf(thrift, thrift.length * 2);
                thrift[len++] = (byte)((nibble(buf[i]) << 4) | nibble(buf[i + 1]));
                i += 2;
            }
            pos = i + 1;
            byte[] t = Arrays.copyOf(thrift, len);
            if ( check )
                ThriftConvert.termFromBytes(term, t);
            long x = objectFile.length();
            NodeId nodeId = NodeIdFactory.createPtr(x);
            objectFile.write(t);
            byte[] bbNodeId = new byte[NodeId.SIZE];
            Bytes.setLong(nodeId.getPtrLocation(), bbNodeId);
            return factory.create(key, bbNodeId);
        }

        private static int nibble(byte b) {
            int v = HEX[b & 0xFF];
            if ( v < 0 )
                throw new IllegalArgumentException("Bad hex char : " + (b & 0xFF));
            return v;
        }
    }

    @Test
    public void benchmark() throws Exception {
        // Fail here, before JMH forks, if the data file is missing.
        XLoaderJmh.dataFile();
        new Runner(XLoaderJmh.options(TestXLoaderTermIndex.class).build()).run();
    }
}
