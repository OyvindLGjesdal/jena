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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.BooleanSupplier;
import java.util.function.LongConsumer;

import org.apache.jena.atlas.lib.Bytes;
import org.apache.jena.atlas.lib.Cache;
import org.apache.jena.atlas.lib.CacheFactory;
import org.apache.jena.atlas.logging.FmtLog;
import org.apache.jena.dboe.base.record.Record;
import org.apache.jena.dboe.base.record.RecordFactory;
import org.apache.jena.dboe.index.Index;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.Triple;
import org.apache.jena.query.TxnType;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.system.StreamRDF;
import org.apache.jena.riot.system.StreamRDFBase;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.tdb2.TDBException;
import org.apache.jena.tdb2.lib.NodeLib;
import org.apache.jena.tdb2.store.Hash;
import org.apache.jena.tdb2.store.NodeId;
import org.apache.jena.tdb2.store.NodeIdFactory;
import org.apache.jena.tdb2.store.nodetable.NodeTable;
import org.apache.jena.tdb2.store.nodetable.NodeTableTRDF;
import org.apache.jena.tdb2.sys.SystemTDB;
import org.apache.jena.tdb2.sys.TDBInternal;

/**
 * The ingest step on several threads ({@link ParallelParser}), for N-Triples and N-Quads.
 * <p>
 * The calling thread holds the ingest write transaction. Each worker parses chunks and
 * finds the NodeId of every node itself, in its own read transaction (TDB2 allows many
 * readers beside the writer): inline values directly; others by hash in the node table's
 * B+tree, as {@code NodeTableNative} does but without its lock, with a cache shared by
 * the workers ({@link #SharedCache}). With a {@link CompactNodeTable} (the node table in
 * memory), a cache miss looks there first, except for blank nodes.
 * The node table step has normally added every node, so lookups find them; a node that
 * is missing (for example a blank node without a shared seed) is sent to the calling
 * thread, which allocates it in the write transaction ({@code getAllocateNodeId}) and
 * returns the NodeId. A worker's read transaction does not see such allocations, so the
 * returned NodeId goes into the cache; a worker missing the same node before that asks
 * again and gets the same NodeId from the write transaction.
 * <p>
 * Each worker writes a chunk's rows to buffers, then appends them to the triples and
 * quads workfiles under a lock. Row order does not matter: each index build sorts the
 * workfile. Rows and counts are as {@link ProcIngestDataX.IngestData} makes them.
 */
final class ParallelIngest {

    record Counts(long triples, long quads) {}

    private record Allocation(Node node, CompletableFuture<NodeId> result) {}

    /**
     * Node to NodeId cache entries in total (as ingest's cache), 10 million unless the
     * system property {@code jena.xloader.ingest.cacheSize} is set. A smaller cache allows
     * a smaller heap, leaving more memory for the page cache of the node table.
     * 0 (the default): from the system property, read by {@link #cacheSize()}, so a bad
     * value is a {@link TDBException}, not an error initializing this class.
     */
    static int CacheSize = 0;

    /** {@link #CacheSize}, or the system property; a bad property value throws {@link TDBException}. */
    static int cacheSize() {
        return CacheSize > 0 ? CacheSize : cacheSize(System.getProperty("jena.xloader.ingest.cacheSize"));
    }

    static int cacheSize(String value) {
        if ( value == null || value.isBlank() )
            return 10_000_000;
        try {
            int size = Integer.parseInt(value.strip().replace("_", ""));
            if ( size >= 1000 )
                return size;
        } catch (NumberFormatException ex) { /* Below */ }
        throw new TDBException("jena.xloader.ingest.cacheSize: expected a number of entries, at least 1000: " + value);
    }

    /**
     * One cache shared by all workers (a concurrent Caffeine cache), so a frequent node is
     * held once, not once per worker, and every worker benefits from the others' lookups.
     * The system property {@code jena.xloader.ingest.sharedCache=false} gives each worker
     * its own share instead (for comparison).
     */
    static boolean SharedCache = !"false".equals(System.getProperty("jena.xloader.ingest.sharedCache"));

    private ParallelIngest() {}

    /**
     * Ingest all of {@code input} (decompressed N-Triples or N-Quads).
     * Must be called in a write transaction on {@code dsg}.
     * {@code table}, if not null, is the node table's hash to NodeId mapping in memory.
     */
    static Counts ingest(DatasetGraph dsg, CompactNodeTable table, InputStream input, Lang lang, String baseIRI, UUID seed,
                         OutputStream outputTriples, OutputStream outputQuads,
                         int threads, int chunkSize, BooleanSupplier cancelled, LongConsumer progress) {
        NodeTable nodeTable = TDBInternal.getDatasetGraphTDB(dsg).getTripleTable().getNodeTupleTable().getNodeTable();
        Index index = ((NodeTableTRDF)nodeTable.baseNodeTable()).getIndex();
        BlockingQueue<Allocation> requests = new LinkedBlockingQueue<>();
        LongAdder triples = new LongAdder();
        LongAdder quads = new LongAdder();
        LongAdder tableFound = new LongAdder();
        LongAdder treeLookups = new LongAdder();
        // Shared: one cache of cacheSize(). Per worker: cacheSize() shared out (at least 100,000 each).
        int totalCacheSize = cacheSize();
        Cache<Node, NodeId> shared = SharedCache ? CacheFactory.createCache(totalCacheSize) : null;
        int cacheSize = Math.max(100_000, totalCacheSize / threads);
        ParallelParser.Owner owner = millis -> {
            for ( Allocation a = requests.poll(millis, TimeUnit.MILLISECONDS) ; a != null ; a = requests.poll() ) {
                try {
                    a.result().complete(nodeTable.getAllocateNodeId(a.node()));
                } catch (RuntimeException | Error ex) {
                    a.result().completeExceptionally(ex);
                    throw ex;
                }
            }
        };
        ParallelParser.parse(input, lang, baseIRI, seed, threads, chunkSize, cancelled, progress,
                             () -> new IngestWorker(dsg, index, table, requests,
                                                    shared != null ? shared : CacheFactory.createCache(cacheSize),
                                                    outputTriples, outputQuads, triples, quads, tableFound, treeLookups),
                             owner);
        if ( table != null )
            FmtLog.info(BulkLoaderX.LOG_Data, "Node table in memory: %,d found there, %,d looked up in the B+tree",
                        tableFound.sum(), treeLookups.sum());
        return new Counts(triples.sum(), quads.sum());
    }

    private static final class IngestWorker implements ParallelParser.Worker {
        private final DatasetGraph dsg;
        private final Index index;
        private final CompactNodeTable table;
        private final RecordFactory factory;
        private final BlockingQueue<Allocation> requests;
        private final Cache<Node, NodeId> cache;
        private final Hash hash = new Hash(SystemTDB.LenNodeHash);
        private final OutputStream outputTriples;
        private final OutputStream outputQuads;
        private final ByteArrayOutputStream bufferTriples = new ByteArrayOutputStream(1 << 20);
        private final ByteArrayOutputStream bufferQuads = new ByteArrayOutputStream(1 << 16);
        private final WriteRows rowsTriples = new WriteRows(bufferTriples, 3, 10_000);
        private final WriteRows rowsQuads = new WriteRows(bufferQuads, 4, 10_000);
        private final LongAdder triples;
        private final LongAdder quads;
        private final LongAdder tableFound;
        private final LongAdder treeLookups;
        private long chunkTableFound = 0;
        private long chunkTreeLookups = 0;
        private long chunkTriples = 0;
        private long chunkQuads = 0;
        private final StreamRDF stream;

        IngestWorker(DatasetGraph dsg, Index index, CompactNodeTable table, BlockingQueue<Allocation> requests, Cache<Node, NodeId> cache,
                     OutputStream outputTriples, OutputStream outputQuads, LongAdder triples, LongAdder quads,
                     LongAdder tableFound, LongAdder treeLookups) {
            this.dsg = dsg;
            this.index = index;
            this.table = table;
            this.tableFound = tableFound;
            this.treeLookups = treeLookups;
            this.factory = index.getRecordFactory();
            this.requests = requests;
            this.cache = cache;
            this.outputTriples = outputTriples;
            this.outputQuads = outputQuads;
            this.triples = triples;
            this.quads = quads;
            // This worker's own read transaction, on this thread.
            dsg.begin(TxnType.READ);
            this.stream = new StreamRDFBase() {
                @Override
                public void triple(Triple triple) {
                    chunkTriples++;
                    process(null, triple.getSubject(), triple.getPredicate(), triple.getObject());
                }

                @Override
                public void quad(Quad quad) {
                    // As IngestData: the default graph is triples.
                    if ( quad.isTriple() || quad.isDefaultGraph() ) {
                        triple(quad.asTriple());
                        return;
                    }
                    chunkQuads++;
                    process(quad.getGraph(), quad.getSubject(), quad.getPredicate(), quad.getObject());
                }
            };
        }

        @Override
        public StreamRDF stream() {
            return stream;
        }

        private void process(Node g, Node s, Node p, Node o) {
            long sId = encode(s);
            long pId = encode(p);
            long oId = encode(o);
            if ( g != null ) {
                rowsQuads.write(encode(g));
                rowsQuads.write(sId);
                rowsQuads.write(pId);
                rowsQuads.write(oId);
                rowsQuads.endOfRow();
            } else {
                rowsTriples.write(sId);
                rowsTriples.write(pId);
                rowsTriples.write(oId);
                rowsTriples.endOfRow();
            }
        }

        private long encode(Node node) {
            return ProcIngestDataX.IngestData.encode(nodeId(node));
        }

        private NodeId nodeId(Node node) {
            NodeId nid = NodeId.inline(node);
            if ( nid != null )
                return nid;
            nid = cache.getIfPresent(node);
            if ( nid != null )
                return nid;
            NodeLib.setHash(hash, node);
            // Not blank nodes: their labels depend on the parse, so the table could
            // match another term's first 64 bits for one the node table step did not add.
            if ( table != null && !node.isBlank() ) {
                long v = table.find(Bytes.getLong(hash.getBytes(), 0));
                if ( v >= 0 ) {
                    chunkTableFound++;
                    nid = NodeIdFactory.createPtr(v);
                    cache.put(node, nid);
                    return nid;
                }
            }
            chunkTreeLookups++;
            Record r = index.find(factory.create(hash.getBytes()));
            nid = ( r != null ) ? NodeIdFactory.get(r.getValue(), 0) : allocate(node);
            cache.put(node, nid);
            return nid;
        }

        /** A node not in the committed node table: allocated by the writer thread. */
        private NodeId allocate(Node node) {
            CompletableFuture<NodeId> result = new CompletableFuture<>();
            try {
                requests.put(new Allocation(node, result));
                return result.get();
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new TDBException("Ingest interrupted", ex);
            } catch (ExecutionException ex) {
                Throwable cause = ex.getCause();
                if ( cause instanceof RuntimeException runtime )
                    throw runtime;
                throw new TDBException("Node allocation failed", cause);
            }
        }

        @Override
        public void endChunk() throws IOException {
            rowsTriples.flush();
            rowsQuads.flush();
            if ( bufferTriples.size() > 0 ) {
                synchronized (outputTriples) {
                    bufferTriples.writeTo(outputTriples);
                }
                bufferTriples.reset();
            }
            if ( bufferQuads.size() > 0 ) {
                synchronized (outputQuads) {
                    bufferQuads.writeTo(outputQuads);
                }
                bufferQuads.reset();
            }
            triples.add(chunkTriples);
            quads.add(chunkQuads);
            tableFound.add(chunkTableFound);
            treeLookups.add(chunkTreeLookups);
            chunkTriples = 0;
            chunkQuads = 0;
            chunkTableFound = 0;
            chunkTreeLookups = 0;
        }

        @Override
        public void close() {
            dsg.end();
        }
    }
}
