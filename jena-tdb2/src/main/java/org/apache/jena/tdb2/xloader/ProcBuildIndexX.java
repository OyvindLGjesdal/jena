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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.atlas.lib.Timer;
import org.apache.jena.atlas.lib.tuple.TupleMap;
import org.apache.jena.atlas.logging.FmtLog;
import org.apache.jena.dboe.base.block.BlockMgr;
import org.apache.jena.dboe.base.file.BufferChannel;
import org.apache.jena.dboe.base.file.Location;
import org.apache.jena.dboe.base.record.Record;
import org.apache.jena.dboe.base.record.RecordFactory;
import org.apache.jena.dboe.sys.Names;
import org.apache.jena.dboe.trans.bplustree.BPlusTree;
import org.apache.jena.dboe.trans.bplustree.BPlusTreeParams;
import org.apache.jena.dboe.trans.bplustree.rewriter.BPlusTreeRewriter;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.system.progress.ProgressIterator;
import org.apache.jena.system.progress.ProgressMonitor;
import org.apache.jena.system.progress.ProgressMonitorOutput;
import org.apache.jena.tdb2.DatabaseMgr;
import org.apache.jena.tdb2.TDBException;
import org.apache.jena.tdb2.loader.base.CoLib;
import org.apache.jena.tdb2.store.DatasetGraphTDB;
import org.apache.jena.tdb2.store.tupletable.TupleIndex;
import org.apache.jena.tdb2.store.tupletable.TupleIndexRecord;
import org.apache.jena.tdb2.sys.SystemTDB;
import org.apache.jena.tdb2.sys.TDBInternal;
import org.slf4j.Logger;

/**
 * From a file of records, build a (packed) index by sorting the input records and
 * the writing the B+Tree bottom up.
 */
public class ProcBuildIndexX
{
    // Sort and build.

    // K1="-k 1,1"
    // K2="-k 2,2"
    // K3="-k 3,3"
    // K4="-k 4,4"
    //
    // generate_index "$K1 $K2 $K3" "$DATA_TRIPLES" SPO
    // generate_index "$K2 $K3 $K1" "$DATA_TRIPLES" POS
    // generate_index "$K3 $K1 $K2" "$DATA_TRIPLES" OSP
    // generate_index "$K1 $K2 $K3 $K4" "$DATA_QUADS" GSPO
    // generate_index "$K1 $K3 $K4 $K2" "$DATA_QUADS" GPOS
    // generate_index "$K1 $K4 $K2 $K3" "$DATA_QUADS" GOSP
    // generate_index "$K2 $K3 $K4 $K1" "$DATA_QUADS" SPOG
    // generate_index "$K3 $K4 $K2 $K1" "$DATA_QUADS" POSG
    // generate_index "$K4 $K2 $K3 $K1" "$DATA_QUADS" OSPG

    public static void exec(String location, String indexName, int sortThreads, /*unused*/String sortIndexArgs, XLoaderFiles loaderFiles) {
        exec(location, indexName, BulkLoaderX.DefaultSortProgram, null, sortThreads, sortIndexArgs, loaderFiles);
    }

    /**
     * Build an index using the given sort program, which must accept the GNU sort(1) options used here,
     * and the given program for compressing sort's temporary files.
     * A null sort program means {@link BulkLoaderX#DefaultSortProgram}; a null compress program means gzip.
     */
    public static void exec(String location, String indexName, String sortProgram, String sortCompressProgram,
                            int sortThreads, /*unused*/String sortIndexArgs, XLoaderFiles loaderFiles) {

        Timer timer = new Timer();
        FmtLog.info(BulkLoaderX.LOG_Index, "Build index %s", indexName);

        timer.startTimer();
        long items = ProcBuildIndexX.exec2(location, indexName, BulkLoaderX.sortProgram(sortProgram), sortCompressProgram, sortThreads, sortIndexArgs, loaderFiles);
        long timeMillis = timer.endTimer();

        double xSec = timeMillis/1000.0;
        double rate = items/xSec;
        String elapsedStr = BulkLoaderX.milliToHMS(timeMillis);
        String rateStr = BulkLoaderX.rateStr(items, timeMillis);

        FmtLog.info(BulkLoaderX.LOG_Index, "%s Index %s : %s seconds - %s at %s TPS", BulkLoaderX.StepMarker, indexName, Timer.timeStr(timeMillis), elapsedStr, rateStr);
    }

    /** Index names this class builds. */
    public static final List<String> IndexNames = List.of("SPO", "POS", "OSP", "GSPO", "GPOS", "GOSP", "SPOG", "POSG", "OSPG");

    /**
     * Build several indexes at the same time, one thread and one sort process each,
     * with one database connection. Each index is written by its own B+tree
     * transaction (as when built alone), so the builds are independent.
     * A percentage {@link BulkLoaderX#SortBufferSize} is shared between the sorts.
     * A compressed workfile is decompressed once for all its sorts
     * ({@link SharedWorkfileReader}).
     * If one build fails, the others are cancelled (which stops their sorts) and the
     * first failure is thrown.
     */
    public static void exec(String location, List<String> indexNames, String sortProgram, String sortCompressProgram,
                            int sortThreads, /*unused*/String sortIndexArgs, XLoaderFiles loaderFiles) {
        if ( indexNames.isEmpty() )
            throw new TDBException("No index to build");
        if ( indexNames.size() == 1 ) {
            exec(location, indexNames.get(0), sortProgram, sortCompressProgram, sortThreads, sortIndexArgs, loaderFiles);
            return;
        }
        Set<String> seen = new HashSet<>();
        for ( String name : indexNames ) {
            if ( !IndexNames.contains(name) )
                throw new TDBException("Index name '" + name + "' not recognized");
            // Two builds of one index at the same time would write the same files.
            if ( !seen.add(name) )
                throw new TDBException("Index name '" + name + "' given more than once");
        }
        String bufferSize = BulkLoaderX.sortBufferSize(BulkLoaderX.SortBufferSize, indexNames.size());
        String names = String.join(" ", indexNames);
        FmtLog.info(BulkLoaderX.LOG_Index, "Build indexes %s in parallel (sort buffer %s each)", names, bufferSize);
        String program = BulkLoaderX.sortProgram(sortProgram);
        Timer timer = new Timer();
        timer.startTimer();
        DatasetGraph dsg = DatabaseMgr.connectDatasetGraph(location);
        Map<String, SharedWorkfileReader> readers = new HashMap<>();
        try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg);
              BulkLoaderX.Cleanup closeReaders = () -> readers.values().forEach(SharedWorkfileReader::close) ) {
            if ( BulkLoaderX.CompressDataFiles ) {
                // Every build runs at the same time (one thread each), so every sort reads its queue.
                Map<String, Integer> sorts = new HashMap<>();
                for ( String indexName : indexNames )
                    sorts.merge(workfile(indexName, loaderFiles), 1, Integer::sum);
                sorts.forEach((datafile, n) -> {
                    if ( n > 1 && !isEmpty(datafile) )
                        readers.put(datafile, new SharedWorkfileReader(datafile, n));
                });
            }
            ExecutorService executor = Executors.newFixedThreadPool(indexNames.size(),
                    Thread.ofPlatform().name("tdb2-xloader-index-", 0).factory());
            try {
                CompletionService<Object> completion = new ExecutorCompletionService<>(executor);
                List<Future<Object>> futures = new ArrayList<>();
                for ( String indexName : indexNames ) {
                    futures.add(completion.submit(() -> {
                        Timer t = new Timer();
                        t.startTimer();
                        FmtLog.info(BulkLoaderX.LOG_Index, "Build index %s", indexName);
                        long items = buildIndex(dsg, indexName, program, sortCompressProgram, sortThreads, bufferSize, sortIndexArgs, loaderFiles,
                                                readers.get(workfile(indexName, loaderFiles)));
                        long millis = t.endTimer();
                        FmtLog.info(BulkLoaderX.LOG_Index, "%s Index %s : %s seconds - %s at %s TPS", BulkLoaderX.StepMarker, indexName,
                                    Timer.timeStr(millis), BulkLoaderX.milliToHMS(millis), BulkLoaderX.rateStr(items, millis));
                        return null;
                    }));
                }
                awaitAll(completion, futures);
            } finally {
                // Wait for every build to end before the dataset is expelled.
                executor.shutdownNow();
                awaitTermination(executor);
            }
        }
        long millis = timer.endTimer();
        FmtLog.info(BulkLoaderX.LOG_Index, "%s Indexes %s : %s seconds - %s", BulkLoaderX.StepMarker, names,
                    Timer.timeStr(millis), BulkLoaderX.milliToHMS(millis));
    }

    /** Wait for all builds, in completion order; on the first failure cancel the rest and throw it. */
    private static void awaitAll(CompletionService<Object> completion, List<Future<Object>> futures) {
        for ( int i = 0 ; i < futures.size() ; i++ ) {
            try {
                completion.take().get();
            } catch (InterruptedException ex) {
                futures.forEach(f -> f.cancel(true));
                Thread.currentThread().interrupt();
                throw new TDBException("Interrupted while building indexes", ex);
            } catch (ExecutionException ex) {
                // Interrupting a build stops its sort process (SortProcess.close).
                futures.forEach(f -> f.cancel(true));
                Throwable cause = ex.getCause();
                if ( cause instanceof RuntimeException runtime )
                    throw runtime;
                if ( cause instanceof Error error )
                    throw error;
                throw new TDBException("Index build failed", cause);
            }
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

    private static long exec2(String location, String indexName, String sortProgram, String sortCompressProgram, int sortThreads, String sortIndexArgs, XLoaderFiles loaderFiles) {
        DatasetGraph dsg = DatabaseMgr.connectDatasetGraph(location);
        try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
            return buildIndex(dsg, indexName, sortProgram, sortCompressProgram, sortThreads, BulkLoaderX.SortBufferSize, sortIndexArgs, loaderFiles, null);
        }
    }

    /** The workfile an index is built from: triples for a triple index, else quads. */
    private static String workfile(String indexName, XLoaderFiles loaderFiles) {
        return indexName.length() == 3 ? loaderFiles.triplesFile : loaderFiles.quadsFile;
    }

    /** Build one index; {@code reader}, if not null, is the shared reader of its workfile. */
    private static long buildIndex(DatasetGraph dsg, String indexName, String sortProgram, String sortCompressProgram, int sortThreads, String sortBufferSize, String sortIndexArgs, XLoaderFiles loaderFiles,
                                   SharedWorkfileReader reader) {
        long tickPoint = BulkLoaderX.DataTick;
        int superTick = BulkLoaderX.DataSuperTick;
        String K1 = "--key=1,1";
        String K2 = "--key=2,2";
        String K3 = "--key=3,3";
        String K4 = "--key=4,4";

        List<String> keys = switch (indexName) {
            case "SPO" -> List.of(K1, K2, K3);
            case "POS" -> List.of(K2, K3, K1);
            case "OSP" -> List.of(K3, K1, K2);
            case "GSPO" -> List.of(K1, K2, K3, K4);
            case "GPOS" -> List.of(K1, K3, K4, K2);
            case "GOSP" -> List.of(K1, K4, K2, K3);
            case "SPOG" -> List.of(K2, K3, K4, K1);
            case "POSG" -> List.of(K3, K4, K2, K1);
            case "OSPG" -> List.of(K4, K2, K3, K1);
            default -> throw new TDBException("Index name '" + indexName + "' not recognized");
        };
        return sort_build_index(BulkLoaderX.LOG_Index, workfile(indexName, loaderFiles), dsg, indexName, sortProgram, sortCompressProgram, sortThreads, sortBufferSize, sortIndexArgs,
                                tickPoint, superTick, loaderFiles.TMPDIR, keys, reader);
    }

    private static boolean isEmpty(String datafile) {
        // If empty file, do nothing.
        Path pathData = Paths.get(datafile);
        try {
            if ( Files.isDirectory(pathData) ) {}
            long x = Files.size(pathData);
            return x == 0;
        } catch (IOException ex) {
            IO.exception(ex);
            return true;
        }
    }

    private static long sort_build_index(Logger LOG, String datafile, DatasetGraph dsg, String indexName,
                                         String sortProgram, String sortCompressProgram, int sortThreads, String sortBufferSize, String sortIndexArgs, long tickPoint, int superTick,
                                         String TMPDIR,
                                         List<String>sortKeyArgs, SharedWorkfileReader reader) {
        if ( isEmpty(datafile) )
            return 0;
        if ( sortThreads <= 0 )
            sortThreads = 2;
        List<String> sortCmd = new ArrayList<>(Arrays.asList(
                sortProgram,
                "--temporary-directory="+TMPDIR,
                "--buffer-size="+sortBufferSize,
                "--parallel="+sortThreads,
                "--unique"
        ));
        if ( BulkLoaderX.CompressSortIndexFiles )
            sortCmd.add("--compress-program="+BulkLoaderX.sortCompressProgram(sortCompressProgram));
        sortCmd.addAll(sortKeyArgs);
        if ( !BulkLoaderX.CompressDataFiles )
            sortCmd.add(datafile);

        SortProcess.Producer producer = ( reader != null ) ? reader.producer() : output -> {
            if ( BulkLoaderX.CompressDataFiles ) {
                try ( InputStream inData = IO.openFile(datafile) ) {
                    inData.transferTo(output);
                }
            }
            // SortProcess closes stdin, including when it is unused.
        };
        try ( SortProcess sort = new SortProcess(sortCmd) ) {
            return sort.run(producer, (input, checkSuccess) -> indexBuilder(dsg, input, indexName, checkSuccess));
        }
    }

    private static long indexBuilder(DatasetGraph dsg, InputStream input, String indexName, Runnable checkSuccess) {
        long tickPoint = BulkLoaderX.DataTick;
        int superTick = BulkLoaderX.DataSuperTick;

        // Location of storage, not the DB.
        DatasetGraphTDB dsgtdb = TDBInternal.getDatasetGraphTDB(dsg);

        int keyLength = SystemTDB.SizeOfNodeId * indexName.length();
        int valueLength = 0;

        // The name is the order. Input is already in the right order.

        int tupleLength = indexName.length();

        TupleIndex index = TDBInternal.findIndex(dsg, indexName);
        if ( index == null )
            throw new TDBException("Can not find index: " + indexName);

        String primaryOrder;
        if ( tupleLength == 3 ) {
            primaryOrder = Names.primaryIndexTriples;
        } else if ( tupleLength == 4 ) {
            primaryOrder = Names.primaryIndexQuads;
        } else {
            throw new TDBException("Index name: " + indexName);
        }
        TupleMap colMap = TupleMap.create(primaryOrder, indexName);

        int blockSize = SystemTDB.BlockSize;
        RecordFactory recordFactory = ((TupleIndexRecord)index).getRangeIndex().getRecordFactory();

        int order = BPlusTreeParams.calcOrder(blockSize, recordFactory);
        BPlusTreeParams bptParams = new BPlusTreeParams(order, recordFactory);

        // Extract from index.
        TupleIndexRecord tIdxRec = (TupleIndexRecord)index;
        BPlusTree bpt = (BPlusTree)(tIdxRec.getRangeIndex());
        BlockMgr blkMgrNodes = bpt.getNodeManager().getBlockMgr();
        BlockMgr blkMgrRecords = bpt.getRecordsMgr().getBlockMgr();
        BufferChannel blkState = bpt.getStateManager().getBufferChannel();
        // ----
        int rowBlock = 1000;
        Iterator<Record> iter = new RecordsFromInput(input, tupleLength, colMap, rowBlock);
        // ProgressMonitor.
        ProgressMonitor monitor = ProgressMonitorOutput.create(BulkLoaderX.LOG_Index, indexName, tickPoint, superTick);
        ProgressIterator<Record> iter2 = new ProgressIterator<>(iter, monitor);

        monitor.start();

        // Independent transaction on just this BPlusTree, not the dataset.
        CoLib.executeWrite(index, ()->{
            BPlusTree bpt2 = BPlusTreeRewriter.packIntoBPlusTree(iter2, bptParams, recordFactory, blkState, blkMgrNodes, blkMgrRecords);
            checkSuccess.run();
        });
        monitor.finish();

        long count = monitor.getTicks();
        return count;
    }

    // No longer used. Fixed for JENA-2294. Delete eventually.
    private static long indexBuilder0(DatasetGraph dsg, InputStream input, String indexName) {
        // This code does not use the setup of the DatasetGraph - it creates the BPTrees and the state file.
        long tickPoint = BulkLoaderX.DataTick;
        int superTick = BulkLoaderX.DataSuperTick;

        // Location of storage, not the DB.
        DatasetGraphTDB dsgtdb = TDBInternal.getDatasetGraphTDB(dsg);
        Location location = dsgtdb.getLocation();

        int keyLength = SystemTDB.SizeOfNodeId * indexName.length();
        int valueLength = 0;

        // The name is the order.
        //String primary = indexName;

        String primaryOrder;
        int dftKeyLength;
        int dftValueLength;
        int tupleLength = indexName.length();

        TupleIndex index;
        if ( tupleLength == 3 ) {
            primaryOrder = Names.primaryIndexTriples;
            dftKeyLength = SystemTDB.LenIndexTripleRecord;
            dftValueLength = 0;
            // Find index.
            index = findIndex0(dsgtdb.getTripleTable().getNodeTupleTable().getTupleTable().getIndexes()
                             , indexName);
        } else if ( tupleLength == 4 ) {
            primaryOrder = Names.primaryIndexQuads;
            dftKeyLength = SystemTDB.LenIndexQuadRecord;
            dftValueLength = 0;
            index = findIndex0(dsgtdb.getQuadTable().getNodeTupleTable().getTupleTable().getIndexes()
                             , indexName);
        } else {
            throw new TDBException("Index name: " + indexName);
        }

        TupleMap colMap = TupleMap.create(primaryOrder, indexName);

        int readCacheSize = 10;
        int writeCacheSize = 100;

        int blockSize = SystemTDB.BlockSize;
        RecordFactory recordFactory = new RecordFactory(dftKeyLength, dftValueLength);

        int order = BPlusTreeParams.calcOrder(blockSize, recordFactory);
        BPlusTreeParams bptParams = new BPlusTreeParams(order, recordFactory);

        int blockSizeNodes = blockSize;
        int blockSizeRecords = blockSize;

        // Extract from index.
        TupleIndexRecord tIdxRec = (TupleIndexRecord)index;
        BPlusTree bpt = (BPlusTree)(tIdxRec.getRangeIndex());
        BlockMgr blkMgrNodes = bpt.getNodeManager().getBlockMgr();
        BlockMgr blkMgrRecords = bpt.getRecordsMgr().getBlockMgr();
        BufferChannel blkState = bpt.getStateManager().getBufferChannel();
        // ----
        int rowBlock = 1000;
        Iterator<Record> iter = new RecordsFromInput(input, tupleLength, colMap, rowBlock);
        // ProgressMonitor.
        ProgressMonitor monitor = ProgressMonitorOutput.create(BulkLoaderX.LOG_Index, indexName, tickPoint, superTick);
        ProgressIterator<Record> iter2 = new ProgressIterator<>(iter, monitor);

        monitor.start();

        // Independent transaction on just this BPlusTree, not the dataset.
        CoLib.executeWrite(index, ()->{
            BPlusTree bpt2 = BPlusTreeRewriter.packIntoBPlusTree(iter2, bptParams, recordFactory, blkState, blkMgrNodes, blkMgrRecords);
        });
        monitor.finish();

        long count = monitor.getTicks();
        return count;
    }

    private static TupleIndex findIndex0(TupleIndex[] indexes, String indexName) {
        for ( TupleIndex idx : indexes ) {
            if ( indexName.equals(idx.getName()) )
                return idx;
        }
        throw new TDBException("Failed to find index: "+indexName+" in "+Arrays.asList(indexes));
    }
}
