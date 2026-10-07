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
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;

import org.apache.jena.atlas.lib.BitsLong;
import org.apache.jena.atlas.lib.Cache;
import org.apache.jena.atlas.lib.CacheFactory;
import org.apache.jena.atlas.lib.FileOps;
import org.apache.jena.dboe.base.file.Location;
import org.apache.jena.dboe.base.record.Record;
import org.apache.jena.dboe.base.record.RecordFactory;
import org.apache.jena.dboe.index.Index;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.Triple;
import org.apache.jena.query.TxnType;
import org.apache.jena.riot.system.AsyncParser;
import org.apache.jena.riot.system.StreamRDFBase;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.system.progress.ProgressMonitor;
import org.apache.jena.system.progress.ProgressMonitorFactory;
import org.apache.jena.tdb2.DatabaseMgr;
import org.apache.jena.tdb2.lib.NodeLib;
import org.apache.jena.tdb2.params.StoreParams;
import org.apache.jena.tdb2.store.DatasetGraphTDB;
import org.apache.jena.tdb2.store.Hash;
import org.apache.jena.tdb2.store.NodeId;
import org.apache.jena.tdb2.store.NodeIdFactory;
import org.apache.jena.tdb2.store.nodetable.NodeTable;
import org.apache.jena.tdb2.store.nodetable.NodeTableTRDF;
import org.apache.jena.tdb2.store.value.DoubleNode62;
import org.apache.jena.tdb2.sys.DatabaseConnection;
import org.apache.jena.tdb2.sys.SystemTDB;
import org.apache.jena.tdb2.sys.TDBInternal;

/**
 * Would parsing the input only once help the ingest step?
 * <p>
 * Setup (not timed) builds the node table for the file named by {@code XLOADER_JMH_DATA}
 * with the real node table stage (which needs GNU sort, or {@code XLOADER_JMH_SORT}), then
 * parses the file once more and writes a "hash file": for each triple position either the
 * encoded inline NodeId or the 128-bit node hash, as a single-parse node stage could.
 * <ul>
 * <li>{@code ingest}: the ingest step as now: parse ({@link AsyncParser}) and look up
 * each node through the node table, with its 10M node-to-NodeId cache, starting cold.</li>
 * <li>{@code resolve}: read the hash file and look up each hash in the node B+tree.</li>
 * <li>{@code resolveCached}: the same with a cold 10M-entry hash-to-NodeId cache.</li>
 * </ul>
 * Blank nodes get new labels in each parse, so their hashes are not in the node table:
 * {@code ingest} allocates them, {@code resolve} counts them as missing (setup checks
 * that only those are missing).
 * <p>
 * All write NodeId rows with {@link WriteRows} to a null stream, as ingest writes its
 * workfile without the gzip. The difference between {@code ingest} and {@code resolve} is
 * roughly what a single parse could save; it costs the hash file (up to 51 bytes per triple).
 * <p>
 * Temporary files go under {@code XLOADER_JMH_TMP} (default: java.io.tmpdir).
 */
@State(Scope.Benchmark)
public class TestXLoaderIngest {

    private static final int CACHE_SIZE = 10_000_000;
    private static final byte INLINE = 0;
    private static final byte HASH = 1;

    private Path work;
    private String datafile;
    private String location;
    private Path hashFile;
    private DatasetGraph dsg;
    private long blankPositions;

    @Setup(Level.Trial)
    public void setup() throws IOException {
        datafile = XLoaderJmh.dataFile();
        String tmp = System.getenv("XLOADER_JMH_TMP");
        Path tmpDir = ( tmp == null || tmp.isBlank() ) ? Path.of(System.getProperty("java.io.tmpdir")) : Path.of(tmp);
        work = Files.createTempDirectory(tmpDir, "xloader-jmh-ingest");
        location = work.resolve("db").toString();
        FileOps.ensureDir(location);
        Path tmpdir = Files.createDirectory(work.resolve("tmp"));
        ProcBuildNodeTableX.exec(location, new XLoaderFiles(tmpdir.toString()), System.getenv("XLOADER_JMH_SORT"),
                                 null, 2, null, List.of(datafile));
        hashFile = work.resolve("hashes.bin");
        writeHashFile();
        // Every hash must be in the node table, except blank nodes: each parse gives them new
        // labels, so the node table stage's entry is never found again. Ingest allocates them
        // anew; resolve cannot without the node, which is negligible for a few of them.
        connect();
        long missing = resolve(false);
        if ( missing != blankPositions ) {
            throw new IllegalStateException(missing + " hashes not found in the node table; expected "
                                            + blankPositions + " (blank nodes)");
        }
    }

    /** A fresh connection per iteration, so the node table cache starts cold as in ingest. */
    @Setup(Level.Iteration)
    public void connect() {
        if ( dsg != null )
            TDBInternal.expel(dsg);
        DatasetGraph dsg0 = DatabaseMgr.connectDatasetGraph(location);
        StoreParams params = TDBInternal.getDatasetGraphTDB(dsg0).getStoreParams();
        TDBInternal.expel(dsg0);
        // As ProcIngestDataX.getDatasetGraph
        params = StoreParams.builder("xloader", params).node2NodeIdCacheSize(CACHE_SIZE).build();
        dsg = DatabaseConnection.connectCreate(Location.create(location), params, null).getDatasetGraph();
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        if ( dsg != null )
            TDBInternal.expel(dsg);
        dsg = null;
        FileOps.clearAll(work.toString());
        work.toFile().delete();
    }

    @Benchmark
    public long ingest() {
        DatasetGraphTDB dsgtdb = TDBInternal.getDatasetGraphTDB(dsg);
        // Counts only, no output.
        ProgressMonitor monitor = ProgressMonitorFactory.progressMonitor("Ingest", null, 0, 0);
        OutputStream nul = OutputStream.nullOutputStream();
        dsg.begin(TxnType.WRITE);
        try {
            ProcIngestDataX.IngestData sink = new ProcIngestDataX.IngestData(dsgtdb, monitor, nul, nul, false);
            sink.startBulk();
            AsyncParser.asyncParse(datafile, sink);
            sink.finishBulk();
            return sink.tripleCount();
        } finally {
            dsg.abort();
        }
    }

    @Benchmark
    public long resolve() throws IOException {
        return resolve(false);
    }

    @Benchmark
    public long resolveCached() throws IOException {
        return resolve(true);
    }

    /** @return the number of hashes not found */
    private long resolve(boolean cached) throws IOException {
        Index index = nodeIndex();
        RecordFactory factory = index.getRecordFactory();
        Cache<ByteBuffer, Long> cache = cached ? CacheFactory.createCache(CACHE_SIZE) : null;
        WriteRows rows = new WriteRows(OutputStream.nullOutputStream(), 3, 100_000);
        long missing = 0;
        dsg.begin(TxnType.READ);
        try ( DataInputStream in =
                new DataInputStream(new BufferedInputStream(Files.newInputStream(hashFile), 1 << 20)) ) {
            byte[] key = new byte[SystemTDB.LenNodeHash];
            for ( ;; ) {
                for ( int i = 0 ; i < 3 ; i++ ) {
                    int tag = in.read();
                    if ( tag < 0 ) {
                        if ( i != 0 )
                            throw new EOFException("Incomplete row in hash file");
                        rows.flush();
                        return missing;
                    }
                    if ( tag == INLINE ) {
                        rows.write(in.readLong());
                        in.readLong();      // Padding
                        continue;
                    }
                    in.readFully(key);
                    Long value = cached ? cache.getIfPresent(ByteBuffer.wrap(key)) : null;
                    if ( value == null ) {
                        Record r = index.find(factory.create(key));
                        if ( r == null ) {
                            missing++;
                            value = -1L;
                        } else {
                            value = encode(NodeIdFactory.get(r.getValue(), 0));
                        }
                        if ( cached )
                            cache.put(ByteBuffer.wrap(key.clone()), value);
                    }
                    rows.write(value);
                }
                rows.endOfRow();
            }
        } finally {
            dsg.end();
        }
    }

    /** Thread count for {@link #resolveCachedParallel} only. */
    @State(Scope.Benchmark)
    public static class Threads {
        @Param({"1", "2", "4", "8"})
        public int threads;
    }

    /**
     * {@code resolveCached} split between threads, each with its own read transaction
     * (TDB2 allows many at once) and its own cache ({@value #CACHE_SIZE} entries in total).
     * Measures whether node lookups in ingest could run in parallel.
     */
    @Benchmark
    public long resolveCachedParallel(Threads t) throws Exception {
        long rows = Files.size(hashFile) / ROW_BYTES;
        ExecutorService executor = Executors.newFixedThreadPool(t.threads);
        try {
            List<Future<Long>> parts = new ArrayList<>();
            for ( int i = 0 ; i < t.threads ; i++ ) {
                long from = rows * i / t.threads;
                long to = rows * (i + 1) / t.threads;
                int cacheSize = CACHE_SIZE / t.threads;
                parts.add(executor.submit(() -> resolveRange(from, to, cacheSize)));
            }
            long missing = 0;
            for ( Future<Long> f : parts )
                missing += f.get();
            return missing;
        } finally {
            executor.shutdownNow();
        }
    }

    private static final int RECORD_BYTES = 1 + SystemTDB.LenNodeHash;
    private static final int ROW_BYTES = 3 * RECORD_BYTES;

    /** Resolve rows [from, to) of the hash file in this thread's own read transaction. */
    private long resolveRange(long from, long to, int cacheSize) throws IOException {
        Index index = nodeIndex();
        RecordFactory factory = index.getRecordFactory();
        Cache<ByteBuffer, Long> cache = CacheFactory.createCache(cacheSize);
        WriteRows rows = new WriteRows(OutputStream.nullOutputStream(), 3, 100_000);
        long missing = 0;
        dsg.begin(TxnType.READ);
        try ( InputStream raw = Files.newInputStream(hashFile) ) {
            raw.skipNBytes(from * ROW_BYTES);
            DataInputStream in = new DataInputStream(new BufferedInputStream(raw, 1 << 20));
            byte[] key = new byte[SystemTDB.LenNodeHash];
            for ( long r = from ; r < to ; r++ ) {
                for ( int i = 0 ; i < 3 ; i++ ) {
                    int tag = in.read();
                    if ( tag == INLINE ) {
                        rows.write(in.readLong());
                        in.readLong();
                        continue;
                    }
                    in.readFully(key);
                    Long value = cache.getIfPresent(ByteBuffer.wrap(key));
                    if ( value == null ) {
                        Record rec = index.find(factory.create(key));
                        if ( rec == null ) {
                            missing++;
                            value = -1L;
                        } else {
                            value = encode(NodeIdFactory.get(rec.getValue(), 0));
                        }
                        cache.put(ByteBuffer.wrap(key.clone()), value);
                    }
                    rows.write(value);
                }
                rows.endOfRow();
            }
            rows.flush();
            return missing;
        } finally {
            dsg.end();
        }
    }

    private Index nodeIndex() {
        NodeTable nt = TDBInternal.getDatasetGraphTDB(dsg).getTripleTable().getNodeTupleTable().getNodeTable();
        return ((NodeTableTRDF)nt.baseNodeTable()).getIndex();
    }

    private void writeHashFile() throws IOException {
        try ( DataOutputStream out =
                new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(hashFile), 1 << 20)) ) {
            Hash hash = new Hash(SystemTDB.LenNodeHash);
            AsyncParser.asyncParse(datafile, new StreamRDFBase() {
                @Override
                public void triple(Triple triple) {
                    try {
                        position(triple.getSubject());
                        position(triple.getPredicate());
                        position(triple.getObject());
                    } catch (IOException ex) {
                        throw new UncheckedIOException(ex);
                    }
                }

                @Override
                public void quad(Quad quad) {
                    throw new UnsupportedOperationException("Triples only");
                }

                private void position(Node node) throws IOException {
                    NodeId nid = NodeId.inline(node);
                    if ( nid != null ) {
                        // Padded to the size of a hash: fixed-size records split evenly between threads.
                        out.write(INLINE);
                        out.writeLong(encode(nid));
                        out.writeLong(0);
                        return;
                    }
                    if ( node.isBlank() )
                        blankPositions++;
                    NodeLib.setHash(hash, node);
                    out.write(HASH);
                    out.write(hash.getBytes());
                }
            });
        }
    }

    /** As ProcIngestDataX.IngestData.encode. */
    private static long encode(NodeId nodeId) {
        long x = nodeId.getPtrLocation();
        switch (nodeId.type()) {
            case PTR :
                return x;
            case XSD_DOUBLE :
                return DoubleNode62.insertType(x);
            default :
                x = BitsLong.pack(x, nodeId.getTypeValue(), 56, 62);
                return BitsLong.set(x, 63);
        }
    }

    @Test
    public void benchmark() throws Exception {
        // Fail here, before JMH forks, if the data file is missing.
        XLoaderJmh.dataFile();
        new Runner(XLoaderJmh.options(TestXLoaderIngest.class).build()).run();
    }
}
