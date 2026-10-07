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
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.atlas.iterator.IteratorSlotted;
import org.apache.jena.atlas.lib.*;
import org.apache.jena.atlas.lib.Timer;
import org.apache.jena.atlas.logging.FmtLog;
import org.apache.jena.dboe.base.file.BinaryDataFile;
import org.apache.jena.dboe.base.file.BufferChannel;
import org.apache.jena.dboe.base.file.FileFactory;
import org.apache.jena.dboe.base.file.FileSet;
import org.apache.jena.dboe.base.record.Record;
import org.apache.jena.dboe.base.record.RecordFactory;
import org.apache.jena.dboe.sys.Names;
import org.apache.jena.dboe.trans.bplustree.BPlusTree;
import org.apache.jena.dboe.trans.bplustree.BPlusTreeParams;
import org.apache.jena.dboe.trans.bplustree.rewriter.BPlusTreeRewriter;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.Triple;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFParserBuilder;
import org.apache.jena.riot.system.AsyncParser;
import org.apache.jena.riot.system.StreamRDF;
import org.apache.jena.riot.thrift.RiotThriftException;
import org.apache.jena.riot.thrift.ThriftConvert;
import org.apache.jena.riot.thrift.wire.RDF_Term;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.system.progress.ProgressIterator;
import org.apache.jena.system.progress.ProgressMonitorOutput;
import org.apache.jena.system.progress.ProgressStreamRDF;
import org.apache.jena.tdb2.DatabaseMgr;
import org.apache.jena.tdb2.TDBException;
import org.apache.jena.tdb2.lib.NodeLib;
import org.apache.jena.tdb2.store.DatasetGraphTDB;
import org.apache.jena.tdb2.store.Hash;
import org.apache.jena.tdb2.store.NodeId;
import org.apache.jena.tdb2.store.NodeIdFactory;
import org.apache.jena.tdb2.store.nodetable.NodeTable;
import org.apache.jena.tdb2.store.nodetable.NodeTableTRDF;
import org.apache.jena.tdb2.sys.SystemTDB;
import org.apache.jena.tdb2.sys.TDBInternal;
import org.apache.thrift.TException;
import org.apache.thrift.TSerializer;
import org.apache.thrift.protocol.TCompactProtocol;
import org.slf4j.Logger;

/*
 * Build the node table.
 *
 * <ul>
 * <li>Step 1: Extract nodes from the input parser, writes (hash, terms in encoded RDF Thrift).
 * <li>Step 2: Sort by hash and remove duplicates.
 * <li>Step 2: Write node table data file and write node table index (B+tree).
 * </ul>
 * Outcome: complete node table.
 */
public class ProcBuildNodeTableX {
    public static void exec(String location, XLoaderFiles loaderFiles, int sortThreads, String sortNodeTableArgs, List<String> datafiles) {
        exec(location, loaderFiles, BulkLoaderX.DefaultSortProgram, null, sortThreads, sortNodeTableArgs, datafiles);
    }

    /**
     * Build the node table using the given sort program, which must accept the GNU sort(1) options used here,
     * and the given program for compressing sort's temporary files; that is only used if
     * {@link BulkLoaderX#CompressSortNodeTableFiles} is set.
     * A null sort program means {@link BulkLoaderX#DefaultSortProgram}; a null compress program means gzip.
     */
    public static void exec(String location, XLoaderFiles loaderFiles, String sortProgram, String sortCompressProgram,
                            int sortThreads, String sortNodeTableArgs, List<String> datafiles) {
        Timer timer = new Timer();
        timer.startTimer();
        FmtLog.info(BulkLoaderX.LOG_Nodes, "Build node table");
        // A bad jena.xloader.nodes.cacheSize fails now, not at the first N-Triples or N-Quads file.
        if ( BulkLoaderX.ParseThreads > 1 )
            ParallelNodeParser.cacheSize();
//        FmtLog.info(LOG1, "  Database   = %s", location);
//        FmtLog.info(LOG1, "  TMPDIR     = %s", tmpdir==null?"unset":tmpdir);
//        FmtLog.info(LOG1, "  Data files = %s", StrUtils.strjoin(datafiles, " "));
        Pair<Long/*triples or quads*/, Long/*indexed nodes*/> buildCounts =
                ProcBuildNodeTableX.exec2(location, loaderFiles, BulkLoaderX.sortProgram(sortProgram),
                        sortCompressProgram, sortThreads, sortNodeTableArgs, datafiles);
        long timeMillis = timer.endTimer();

        long items = buildCounts.getLeft();
        double xSec = timeMillis/1000.0;
        double rate = items/xSec;
        String elapsedStr = BulkLoaderX.milliToHMS(timeMillis);
        String rateStr = BulkLoaderX.rateStr(items, timeMillis);

        FmtLog.info(BulkLoaderX.LOG_Terms, "%s NodeTable : %s seconds - %s at %s terms per second", BulkLoaderX.StepMarker,
                    Timer.timeStr(timeMillis), elapsedStr, rateStr);
    }

    /** @return Pair<triples, indexed nodes> */
    private static Pair<Long, Long> exec2(String DB, XLoaderFiles loaderFiles, String sortProgram,
            String sortCompressProgram, int sortThreads, String sortNodeTableArgs, List<String> datafiles) {

        DatasetGraph dsg = DatabaseMgr.connectDatasetGraph(DB);
        try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
            return buildNodeTable(dsg, loaderFiles, sortProgram, sortCompressProgram, sortThreads, datafiles);
        }
    }

    private static Pair<Long, Long> buildNodeTable(DatasetGraph dsg, XLoaderFiles loaderFiles,
            String sortProgram, String sortCompressProgram, int sortThreads, List<String> datafiles) {
        DatasetGraphTDB dsgtdb = TDBInternal.getDatasetGraphTDB(dsg);
        NodeTable nt = dsgtdb.getTripleTable().getNodeTupleTable().getNodeTable();
        NodeTableTRDF nodeTable = (NodeTableTRDF)nt.baseNodeTable();

        if ( sortThreads <= 0 )
            sortThreads = 2;
        List<String> sortCmd = new ArrayList<>(Arrays.asList(
                sortProgram,
                "--temporary-directory="+loaderFiles.TMPDIR,
                "--buffer-size="+BulkLoaderX.SortBufferSize,
                "--parallel="+sortThreads,
                "--unique",
                "--key=1,1"
        ));
        if ( BulkLoaderX.CompressSortNodeTableFiles )
            sortCmd.add("--compress-program="+BulkLoaderX.sortCompressProgram(sortCompressProgram));

        AtomicLong countParseTicks = new AtomicLong(-1);
        try ( SortProcess sort = new SortProcess(sortCmd) ) {
            long indexed = sort.run(output -> {
                ProgressMonitorOutput monitor = ProgressMonitorOutput.create(BulkLoaderX.LOG_Nodes,
                        "Nodes", BulkLoaderX.DataTick, BulkLoaderX.DataSuperTick);
                NodeHashTmpStream worker = new NodeHashTmpStream(output);
                LongAdder parallelLines = new LongAdder();
                ProgressStreamRDF stream = new ProgressStreamRDF(worker, monitor);
                monitor.start();
                String label = monitor.getLabel();
                // Shared with ingest, which then finds this step's blank nodes.
                UUID loadSeed = BlankNodeSeed.create(loaderFiles);
                int fileIndex = -1;
                for ( String datafile : datafiles ) {
                    fileIndex++;
                    if ( Thread.currentThread().isInterrupted() )
                        throw new TDBException("Node parsing interrupted");
                    monitor.setLabel(FileOps.basename(datafile));
                    Lang lang = InputFile.lang(datafile);
                    if ( BulkLoaderX.ParseThreads > 1 && ( Lang.NTRIPLES.equals(lang) || Lang.NQUADS.equals(lang) ) ) {
                        // Line-based syntax: parse chunks on several threads.
                        try ( InputFile input = InputFile.open(datafile) ) {
                            ParallelNodeParser.parse(input.stream(), lang, IRILib.filenameToIRI(datafile),
                                    BlankNodeSeed.fileSeed(loadSeed, fileIndex), output,
                                    BulkLoaderX.ParseThreads, BulkLoaderX.ParseChunkSize, sort::isCancelled,
                                    n -> {
                                        synchronized (monitor) {
                                            for ( long i = 0 ; i < n ; i++ )
                                                monitor.tick();
                                        }
                                    },
                                    parallelLines);
                        }
                        continue;
                    }
                    stream.start();
                    try ( InputFile input = InputFile.open(datafile) ) {
                        // Parse on a separate thread; hashing and writing stay on this one.
                        RDFParserBuilder parser =
                                input.parser().labelToNode(BlankNodeSeed.labelToNode(loadSeed, fileIndex));
                        AsyncParser.asyncParseSources(List.of(parser), stream);
                        // AsyncParser returns normally, and clears the interrupt,
                        // if this thread is interrupted while waiting for the parser.
                        if ( sort.isCancelled() )
                            throw new TDBException("Node parsing interrupted");
                    }
                    stream.finish();
                }
                monitor.finish();
                monitor.setLabel(label);
                output.flush();
                long count = monitor.getTicks();
                countParseTicks.set(count);
                FmtLog.info(BulkLoaderX.LOG_Nodes, "%s Parse (nodes): %s seconds : %,d triples/quads %s TPS",
                            BulkLoaderX.StageMarker, Timer.timeStr(monitor.getTime()), count,
                            BulkLoaderX.rateStr(count, monitor.getTime()));
                // Nodes not found in the node cache; the duplicates among them are left to sort.
                FmtLog.info(BulkLoaderX.LOG_Nodes, "Node lines to sort: %,d", worker.lines() + parallelLines.sum());
            }, (input, checkSuccess) -> {
                Timer timer = new Timer();
                FileSet fileSet = new FileSet(dsgtdb.getLocation(), Names.nodeTableBaseName);
                BufferChannel blkState = FileFactory.createBufferChannel(fileSet, Names.extBptState);
                try ( BulkLoaderX.Cleanup closeState = blkState::close ) {
                    ProgressMonitorOutput monitor = ProgressMonitorOutput.create(BulkLoaderX.LOG_Terms,
                            "Index", BulkLoaderX.DataTick, BulkLoaderX.DataSuperTick);
                    dsg.executeWrite(() -> {
                        BinaryDataFile objectFile = nodeTable.getData();
                        SortedNodeRecords records = records(BulkLoaderX.LOG_Terms, input, objectFile);
                        try ( records ) {
                            Iterator<Record> rIter = new ProgressIterator<>(records, monitor);
                            BPlusTree bpt1 = (BPlusTree)nodeTable.getIndex();
                            BPlusTreeParams bptParams = bpt1.getParams();
                            RecordFactory factory = new RecordFactory(SystemTDB.LenNodeHash, NodeId.SIZE);
                            // Wait for sort to produce output before starting the build timer.
                            rIter.hasNext();
                            monitor.start();
                            timer.startTimer();
                            BPlusTree bpt2 = BPlusTreeRewriter.packIntoBPlusTree(rIter,
                                    bptParams, factory, blkState,
                                    bpt1.getNodeManager().getBlockMgr(), bpt1.getRecordsMgr().getBlockMgr());
                            // EOF may be caused by a failed parser or sort: do not commit it.
                            checkSuccess.run();
                            bpt2.sync();
                            objectFile.sync();
                            monitor.finish();
                        }
                    });
                    long elapsed = timer.endTimer();
                    long count = monitor.getTicks();
                    FmtLog.info(BulkLoaderX.LOG_Terms,
                            "%s Index terms: %s seconds : %,d indexed RDF terms : %s PerSecond",
                            BulkLoaderX.StageMarker, Timer.timeStr(elapsed), count,
                            BulkLoaderX.rateStr(count, elapsed));
                    return count;
                }
            });
            return Pair.create(countParseTicks.get(), indexed);
        }
    }

    /**
     * The node table records from the sorted node lines ({@code hash thrift}, in hex).
     * Package-private for benchmarks.
     */
    /*package*/ static SortedNodeRecords records(Logger logger, InputStream input, BinaryDataFile objectFile) {
        return new SortedNodeRecords(input, objectFile, BulkLoaderX.TermThreads);
    }

    public static int hexRead(InputStream input) throws IOException {
        int c1 = input.read();
        if ( c1 < 0 )
            return -1;
        if ( c1 == '\n' || c1 == ' ')
            return -1;
        int c2 = input.read();
        int b1 = Hex.hexByteToInt(c1);
        int b2 = Hex.hexByteToInt(c2);
        int b = (b1<<4)|b2;
        return b;
    }

    public static void hexWrite(OutputStream output, int bits8) throws IOException {
        int x1 = (bits8>>4) & 0xF;
        int x2 = bits8 & 0xF;
        byte ch1 = Bytes.hexDigitsUC[x1];
        byte ch2 = Bytes.hexDigitsUC[x2];
        output.write(ch1);
        output.write(ch2);
    }

    //Cache needed to reduce duplicates
    /** Write the intermediate sort file */
    static class NodeHashTmpStream implements StreamRDF {

        /** Nodes in the cache of recently written nodes. */
        static final int CacheSize = 500_000;

        private final OutputStream outputData;
        // Skips writing a node seen recently; sort --unique removes the duplicates it misses.
        private final CacheSet<Node> cache;
        // Per instance, so parallel parsers can each have their own stream.
        private final Hash hash = new Hash(SystemTDB.LenNodeHash);
        private final TSerializer serializer;
        private long lines = 0;

        NodeHashTmpStream(OutputStream outputFile) {
            this(outputFile, CacheFactory.createCacheSet(CacheSize));
        }

        /** With a given cache, which may be shared by several streams on different threads. */
        NodeHashTmpStream(OutputStream outputFile, CacheSet<Node> cache) {
            this.outputData = outputFile;
            this.cache = cache;
            try {
                this.serializer = new TSerializer(new TCompactProtocol.Factory());
            }
            catch (TException e) {
                throw new RiotThriftException(e);
            }
        }

        @Override
        public void start() {}

        @Override
        public void triple(Triple triple) {
            node(triple.getSubject());
            node(triple.getPredicate());
            node(triple.getObject());
        }

        @Override
        public void quad(Quad quad) {
            node(quad.getGraph());
            node(quad.getSubject());
            node(quad.getPredicate());
            node(quad.getObject());
        }

        private void node(Node node) {
            if ( Thread.currentThread().isInterrupted() )
                throw new TDBException("Node parsing interrupted");
            NodeId nid = NodeId.inline(node);
            if ( nid != null )
                return ;
            if ( cache.contains(node) )
                return;
            cache.add(node);
            // -- Hash of node
            NodeLib.setHash(hash, node);
            try {
                byte k[] = hash.getBytes();
                RDF_Term term = ThriftConvert.convert(node, false);
                byte[] tBytes = serializer.serialize(term);
                write(outputData, k);
                outputData.write(' ');
                write(outputData, tBytes);
                outputData.write('\n');
                lines++;
            } catch (TException | IOException ex) {
                throw new TDBException("Failed to write node to sort", ex);
            }
        }

        /** Lines written for the sort: the nodes not found in the cache. */
        long lines() {
            return lines;
        }

        private static void write(OutputStream outputData, byte[] bytes) throws IOException {
            for ( byte bits8 : bytes )
                hexWrite(outputData, bits8);
        }

        @Override
        public void base(String base) {}

        @Override
        public void prefix(String prefix, String iri) {}

        @Override
        public void version(String version) {}

        @Override
        public void flush() {
            IO.flush(outputData);
        }

        @Override
        public void finish() {
            flush();
        }
    }
}
