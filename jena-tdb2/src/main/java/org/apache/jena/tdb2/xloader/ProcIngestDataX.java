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
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

import org.apache.jena.atlas.RuntimeIOException;
import org.apache.jena.atlas.io.IO;
import org.apache.jena.atlas.json.JSON;
import org.apache.jena.atlas.json.JsonObject;
import org.apache.jena.atlas.lib.BitsLong;
import org.apache.jena.atlas.lib.DateTimeUtils;
import org.apache.jena.atlas.lib.IRILib;
import org.apache.jena.atlas.lib.Pair;
import org.apache.jena.atlas.lib.Timer;
import org.apache.jena.atlas.logging.FmtLog;
import org.apache.jena.dboe.base.file.Location;
import org.apache.jena.dboe.index.Index;
import org.apache.jena.dboe.sys.Names;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.Triple;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFParserBuilder;
import org.apache.jena.riot.system.AsyncParser;
import org.apache.jena.riot.system.StreamRDF;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.system.progress.ProgressMonitor;
import org.apache.jena.system.progress.ProgressMonitorOutput;
import org.apache.jena.tdb2.DatabaseMgr;
import org.apache.jena.tdb2.params.StoreParams;
import org.apache.jena.tdb2.solver.stats.Stats;
import org.apache.jena.tdb2.solver.stats.StatsCollectorNodeId;
import org.apache.jena.tdb2.store.DatasetGraphTDB;
import org.apache.jena.tdb2.store.NodeId;
import org.apache.jena.tdb2.store.nodetable.NodeTable;
import org.apache.jena.tdb2.store.nodetable.NodeTableTRDF;
import org.apache.jena.tdb2.store.nodetupletable.NodeTupleTable;
import org.apache.jena.tdb2.store.value.DoubleNode62;
import org.apache.jena.tdb2.sys.DatabaseConnection;
import org.apache.jena.tdb2.sys.TDBInternal;

/**
 * Load the triples and quads to temporary files.
 * <p>
 * If the node table has been created ({@link ProcBuildNodeTableX}), this step uses
 * it to map Nodes to NodeIds (lookup).
 * <p>
 * If the node table was not created, this step creates the node table and sets the
 * mapping Nodes to NodeIds.
 */
public class ProcIngestDataX {

    // Node Table.
    public static void exec(String location,
                            XLoaderFiles loaderFiles,
                            List<String> datafiles, boolean collectStats) {
        exec(location, loaderFiles, datafiles, collectStats,
             BulkLoaderX.WorkfileGzipLevel, BulkLoaderX.WorkfileGzipBufferSize);
    }

    /**
     * Ingest data, writing the triples and quads workfiles with the given gzip level and buffer size
     * (see {@link IO#openOutputFile(String, int, int)}). These apply when {@link BulkLoaderX#CompressDataFiles} is set.
     */
    public static void exec(String location,
                            XLoaderFiles loaderFiles,
                            List<String> datafiles, boolean collectStats,
                            int gzipLevel, int gzipBufferSize) {
        FmtLog.info(BulkLoaderX.LOG_Data, "Ingest data");
        DatasetGraph dsg = getDatasetGraph(location);
        try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
            if ( BulkLoaderX.PreloadNodeTable )
                preloadNodeTable(TDBInternal.getDatasetGraphTDB(dsg).getLocation());
            ProgressMonitor monitor = ProgressMonitorOutput.create(BulkLoaderX.LOG_Data,
                    "Data", BulkLoaderX.DataTick, BulkLoaderX.DataSuperTick);
            dsg.executeWrite(() -> {
                Pair<Long, Long> counts;
                // Close both intermediate files before publishing load information or
                // committing, including when opening the second output or parsing fails.
                try ( OutputStream triples = IO.ensureBuffered(IO.openOutputFile(loaderFiles.triplesFile, gzipLevel, gzipBufferSize));
                      OutputStream quads = IO.ensureBuffered(IO.openOutputFile(loaderFiles.quadsFile, gzipLevel, gzipBufferSize)) ) {
                    CompactNodeTable table = BulkLoaderX.NodeTableInMemory ? compactNodeTable(dsg) : null;
                    counts = build(dsg, monitor, triples, quads, datafiles, BlankNodeSeed.read(loaderFiles), table);
                } catch (IOException ex) {
                    throw new RuntimeIOException(ex);
                }
                long cTriple = counts.getLeft();
                long cQuad = counts.getRight();
                FmtLog.info(BulkLoaderX.LOG_Data, "Triples = %,d ; Quads = %,d", cTriple, cQuad);
                JsonObject obj = JSON.buildObject(b->{
                    b.pair("ingested", DateTimeUtils.nowAsXSDDateTimeString());
                    b.key("data").startArray();
                    datafiles.forEach(fn->b.value(fn));
                    b.finishArray();
                    b.pair("triples", cTriple);
                    b.pair("quads", cQuad);
                });
                try ( OutputStream out = IO.openOutputFile(loaderFiles.loadInfo) ) {
                    JSON.write(out, obj);
                } catch (IOException ex) { IO.exception(ex); }
            });
        }
    }

    /**
     * Read the node table's B+tree files (hash to NodeId) once, sequentially, so the page
     * cache holds as much of them as fits before ingest's lookups, which go to random
     * places in them. Much faster than the cache filling through random page faults.
     */
    private static void preloadNodeTable(Location storage) {
        Timer timer = new Timer();
        timer.startTimer();
        long bytes = 0;
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocateDirect(8 * 1024 * 1024);
        for ( String ext : List.of(Names.extBptTree, Names.extBptRecords) ) {
            java.nio.file.Path path = java.nio.file.Path.of(storage.getPath(Names.nodeTableBaseName, ext));
            if ( !java.nio.file.Files.isRegularFile(path) )
                continue;
            try ( java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(path) ) {
                int n;
                while ( (n = channel.read(buffer)) != -1 ) {
                    bytes += n;
                    buffer.clear();
                }
            } catch (IOException ex) {
                throw new RuntimeIOException(ex);
            }
        }
        long millis = timer.endTimer();
        FmtLog.info(BulkLoaderX.LOG_Data, "Preload node table: %,d bytes in %s seconds", bytes, Timer.timeStr(millis));
    }

    private static DatasetGraph getDatasetGraph(String location) {
        Location loc = Location.create(location);
        // Ensure reset
        DatasetGraph dsg0 = DatabaseMgr.connectDatasetGraph(location);
        StoreParams storeParams;
        try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg0) ) {
            storeParams = TDBInternal.getDatasetGraphTDB(dsg0).getStoreParams();
        }

        if ( true ) {
            storeParams = StoreParams.builder("xloader", storeParams)
                    .node2NodeIdCacheSize(10_000_000)
                    .build();
        }

        DatasetGraph dsg = DatabaseConnection.connectCreate(loc, storeParams, null).getDatasetGraph();
        StoreParams storeParamsActual = TDBInternal.getDatasetGraphTDB(dsg).getStoreParams();
//        FmtLog.info(LOG, "Node to NodeId cache size: %,d", storeParamsActual.getNode2NodeIdCacheSize());
//        FmtLog.info(LOG, "NodeId to Node cache size: %,d", storeParamsActual.getNodeId2NodeCacheSize());
        return dsg;
    }

    /**
     * The node table's hash to NodeId mapping in memory, from one pass over the B+tree in
     * the current transaction; null if ingest is not parallel or the node table was not
     * built in hash order.
     */
    private static CompactNodeTable compactNodeTable(DatasetGraph dsg) {
        if ( BulkLoaderX.ingestThreads() <= 1 ) {
            FmtLog.warn(BulkLoaderX.LOG_Data, "Node table in memory: only for parallel ingest (ingest threads above 1); not used");
            return null;
        }
        DatasetGraphTDB dsgtdb = TDBInternal.getDatasetGraphTDB(dsg);
        NodeTableTRDF nodeTable = (NodeTableTRDF)dsgtdb.getTripleTable().getNodeTupleTable().getNodeTable().baseNodeTable();
        Index index = nodeTable.getIndex();
        Location location = dsgtdb.getLocation();
        long maxRecords;
        if ( location.isMem() )
            maxRecords = index.size();
        else {
            // The records file holds at most its size in records.
            Path records = Path.of(location.getPath(Names.nodeTableBaseName, Names.extBptRecords));
            try {
                maxRecords = Files.size(records) / index.getRecordFactory().recordLength();
            } catch (IOException ex) {
                throw new RuntimeIOException(ex);
            }
        }
        Timer timer = new Timer();
        timer.startTimer();
        try {
            CompactNodeTable table = CompactNodeTable.build(index.iterator(), maxRecords, nodeTable.getData().length());
            long millis = timer.endTimer();
            FmtLog.info(BulkLoaderX.LOG_Data, "Node table in memory: %,d terms, %,d MB, %s seconds",
                        table.size(), table.bytes() / (1024 * 1024), Timer.timeStr(millis));
            return table;
        } catch (CompactNodeTable.NotApplicable ex) {
            FmtLog.warn(BulkLoaderX.LOG_Data, "Node table in memory: not used: %s", ex.getMessage());
            return null;
        }
    }

    private static Pair<Long, Long> build(DatasetGraph dsg, ProgressMonitor monitor,
                              OutputStream outputTriples, OutputStream outputQuads,
                              List<String> datafiles, UUID blankNodeSeed, CompactNodeTable table) {
        DatasetGraphTDB dsgtdb = TDBInternal.getDatasetGraphTDB(dsg);
        IngestData sink = new IngestData(dsgtdb, monitor, outputTriples, outputQuads, false);
        Timer timer = new Timer();
        timer.startTimer();
        // [BULK] XXX Better :: Start monitor on first item from parser.
        monitor.start();
        sink.startBulk();
        long parallelTriples = 0;
        long parallelQuads = 0;
        if ( BulkLoaderX.ingestThreads() > 1 ) {
            // N-Triples and N-Quads files on several threads; other files as below, one at a time.
            for ( int i = 0 ; i < datafiles.size() ; i++ ) {
                String datafile = datafiles.get(i);
                Lang lang = InputFile.lang(datafile);
                try ( InputFile input = InputFile.open(datafile) ) {
                    if ( Lang.NTRIPLES.equals(lang) || Lang.NQUADS.equals(lang) ) {
                        // Without a seed from the node table step, still one seed for all chunks of the file.
                        UUID seed = ( blankNodeSeed != null ) ? BlankNodeSeed.fileSeed(blankNodeSeed, i) : UUID.randomUUID();
                        ParallelIngest.Counts counts = ParallelIngest.ingest(dsg, table, input.stream(), lang, IRILib.filenameToIRI(datafile), seed,
                                outputTriples, outputQuads, BulkLoaderX.ingestThreads(), BulkLoaderX.ParseChunkSize, () -> false,
                                n -> { synchronized (monitor) { for ( long t = 0 ; t < n ; t++ ) monitor.tick(); } });
                        parallelTriples += counts.triples();
                        parallelQuads += counts.quads();
                    } else {
                        RDFParserBuilder parser = input.parser();
                        if ( blankNodeSeed != null )
                            parser.labelToNode(BlankNodeSeed.labelToNode(blankNodeSeed, i));
                        AsyncParser.asyncParseSources(List.of(parser), sink);
                    }
                }
            }
        } else if ( blankNodeSeed == null ) {
            // No seed from the node table step: as before, each parse labels blank nodes itself.
            AsyncParser.asyncParse(datafiles, sink);
        } else {
            // One file at a time, with blank node labels from the node table step's seed for the file.
            for ( int i = 0 ; i < datafiles.size() ; i++ ) {
                try ( InputFile input = InputFile.open(datafiles.get(i)) ) {
                    RDFParserBuilder parser = input.parser();
                    parser.labelToNode(BlankNodeSeed.labelToNode(blankNodeSeed, i));
                    AsyncParser.asyncParseSources(List.of(parser), sink);
                }
            }
        }
//        for( String filename : datafiles) {
//            if ( datafiles.size() > 0 )
//                cmdLog.info("Load: "+filename+" -- "+DateTimeUtils.nowAsString());
//            RDFParser.source(filename).parse(sink);
//        }
        sink.finishBulk();

        long cTriple = sink.tripleCount() + parallelTriples;
        long cQuad = sink.quadCount() + parallelQuads;

        // ---- Stats

        // See Stats class.
        if ( sink.getCollector() != null ) {
            Location location = dsgtdb.getLocation();
            if ( ! location.isMem() )
                Stats.write(location.getPath(Names.optStats), sink.getCollector().results());
        }

        // ---- Monitor
        monitor.finish();
        long time = timer.endTimer();
        long total = monitor.getTicks();
        float elapsedSecs = time/1000F;
        float rate = (elapsedSecs!=0) ? total/elapsedSecs : 0;
        // [BULK] End stage.
        String str =  String.format("%s Total: %,d tuples : %,.2f seconds : %,.2f tuples/sec [%s]",
                                    BulkLoaderX.StepMarker,
                                    total, elapsedSecs, rate, DateTimeUtils.nowAsString());
        BulkLoaderX.LOG_Data.info(str);
        return Pair.create(cTriple, cQuad);
    }

    static class IngestData implements StreamRDF {
        private DatasetGraphTDB dsg;
        private NodeTable nodeTable;
        long countTriples = 0;
        long countQuads = 0;
        private WriteRows writerTriples;
        private WriteRows writerQuads;
        private ProgressMonitor monitor;
        private StatsCollectorNodeId stats;

        IngestData(DatasetGraphTDB dsg, ProgressMonitor monitor,
                   OutputStream outputTriples, OutputStream outputQuads,
                   boolean collectStats) {
            this.dsg = dsg;
            this.monitor = monitor;
            NodeTupleTable ntt = dsg.getTripleTable().getNodeTupleTable();
            this.nodeTable = ntt.getNodeTable();
            this.writerTriples = new WriteRows(outputTriples, 3, 100_000);
            this.writerQuads = new WriteRows(outputQuads, 4, 100_000);
            if ( collectStats )
                this.stats = new StatsCollectorNodeId(nodeTable);
        }

        // @Override
        public void startBulk() {}

        @Override
        public void start() {}

        @Override
        public void flush() {
            writerTriples.flush();
            writerQuads.flush();

        }

        @Override
        public void finish() {}

        // @Override
        public void finishBulk() {
            flush();
            nodeTable.sync();
            // dsg.getStoragePrefixes().sync();
        }

        @Override
        public void triple(Triple triple) {
            countTriples++;
            Node s = triple.getSubject();
            Node p = triple.getPredicate();
            Node o = triple.getObject();
            process(Quad.tripleInQuad, s, p, o);
        }

        @Override
        public void quad(Quad quad) {
            countQuads++;
            Node s = quad.getSubject();
            Node p = quad.getPredicate();
            Node o = quad.getObject();
            Node g = null;
            // Union graph?!
            if ( !quad.isTriple() && !quad.isDefaultGraph() )
                g = quad.getGraph();
            process(g, s, p, o);
        }

        // --> From NodeIdFactory
        static long encode(NodeId nodeId) {
            long x = nodeId.getPtrLocation(); // Should be "getValue"
            switch (nodeId.type()) {
                case PTR :
                    return x;
                case XSD_DOUBLE :
                    // XSD_DOUBLE is special.
                    // Set value bit (63) and bit 62
                    x = DoubleNode62.insertType(x);
                    return x;
                default :
                    // Bit 62 is zero - tag is for doubles.
                    x = BitsLong.pack(x, nodeId.getTypeValue(), 56, 62);
                    // Set the high, value bit.
                    x = BitsLong.set(x, 63);
                    return x;
            }
        }

        private void write(WriteRows out, NodeId nodeId) {
            long x = encode(nodeId);
            out.write(x);
        }

        private void process(Node g, Node s, Node p, Node o) {
            NodeId sId = nodeTable.getAllocateNodeId(s);
            NodeId pId = nodeTable.getAllocateNodeId(p);
            NodeId oId = nodeTable.getAllocateNodeId(o);

            if ( g != null ) {
                NodeId gId = nodeTable.getAllocateNodeId(g);
                write(writerQuads, gId);
                write(writerQuads, sId);
                write(writerQuads, pId);
                write(writerQuads, oId);
                writerQuads.endOfRow();
                if ( stats != null )
                    stats.record(gId, sId, pId, oId);
            } else {
                write(writerTriples, sId);
                write(writerTriples, pId);
                write(writerTriples, oId);
                writerTriples.endOfRow();
                if ( stats != null )
                    stats.record(null, sId, pId, oId);
            }
            monitor.tick();
        }

        public StatsCollectorNodeId getCollector() {
            return stats;
        }

        public long tripleCount() { return countTriples; }

        public long quadCount()   { return countQuads; }

        @Override
        public void base(String base) {}

        @Override
        public void prefix(String prefix, String iri) {
            dsg.prefixes().add(prefix, iri);
        }

        @Override
        public void version(String version) {}
    }
}
