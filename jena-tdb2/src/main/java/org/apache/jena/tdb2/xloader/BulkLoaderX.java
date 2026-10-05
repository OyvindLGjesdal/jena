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

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.zip.Deflater;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.tdb2.TDBException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BulkLoaderX {
    /** Cleanup actions whose failures are suppressed by try-with-resources. */
    @FunctionalInterface
    interface Cleanup extends AutoCloseable {
        @Override
        void close();
    }

    public static int DataTick = 1_000_000;
    public static int DataSuperTick = 10;

    /**
     * Marker at end of each step with the log message about the statistics.
     * Grep for this in the logs.
     */
    public static final String StepMarker = "==-==-==";

    /**
     * Marker at the start of a stage within a step.
     */
    public static final String StageMarker = "==";

    /**
     * Whether to compress the triple.tmp and quads.tmp files.
     * These are read multiple times.
     */
    public static boolean CompressDataFiles = true;

    /**
     * Gzip level for the compressed triples and quads workfiles.
     * These are written once and read for each index, then discarded,
     * so favour speed over size. {@link Deflater#DEFAULT_COMPRESSION} (-1)
     * is the general Jena default.
     */
    public static final int WorkfileGzipLevel = Deflater.BEST_SPEED;

    /**
     * Gzip output buffer size for the workfiles.
     * The general Jena default, {@link IO#GZIP_BUFSIZE_DEFAULT}, is 512 bytes,
     * which results in many small writes. This matches the 128 KiB buffer that
     * {@link IO#ensureBuffered(java.io.OutputStream)} puts in front of the gzip stream,
     * so each buffered chunk is written out in at most one write.
     */
    public static final int WorkfileGzipBufferSize = 128 * 1024;

    /**
     * Whether to compress intermediate sort files for the node table.
     * We'll need this amount of space for the final indexes so this isn't helpful.
     */
    public static boolean CompressSortNodeTableFiles = false;

    /**
     * Whether to compress intermediate sort files for the indexes.
     */
    public static boolean CompressSortIndexFiles = true;

    /**
     * Default for sort's {@code --buffer-size}: half the machine's memory, for one sort at a time.
     */
    public static final String DefaultSortBufferSize = "50%";

    /**
     * Value of sort's {@code --buffer-size} for every xloader sort.
     * Each xloader step runs in its own JVM, which sets this from its command line.
     */
    public static String SortBufferSize = DefaultSortBufferSize;

    /**
     * The {@code --buffer-size} for each of {@code sorts} sorts running at the same time:
     * a percentage of memory is shared between them (at least 1%); an absolute size, which
     * sort takes as a per-process size, is used by each.
     */
    /*package*/ static String sortBufferSize(String bufferSize, int sorts) {
        if ( sorts > 1 && bufferSize.endsWith("%") ) {
            int percent = Integer.parseInt(bufferSize.substring(0, bufferSize.length() - 1));
            return Math.max(1, percent / sorts) + "%";
        }
        return bufferSize;
    }

    /**
     * Whether a value is a size sort's {@code --buffer-size} accepts: a number,
     * optionally followed by {@code %} or a unit suffix (b, K, M, G, T, P, E, Z, Y).
     */
    public static boolean isSortBufferSize(String bufferSize) {
        return bufferSize != null && bufferSize.matches("[1-9][0-9]*(%|[bKMGTPEZYkmgtpezy])?");
    }

    /**
     * Threads parsing N-Triples and N-Quads input in the node table step; 1 (the default)
     * parses as before, with one parser thread ({@link ParallelNodeParser} otherwise).
     */
    public static int ParseThreads = 1;

    /**
     * Threads for the ingest step; 0 (the default) means {@link #ParseThreads}. Ingest is
     * limited by node lookups waiting for the disk once the node table is larger than
     * memory; more threads keep more reads in flight than parsing alone would need.
     */
    public static int IngestThreads = 0;

    /**
     * Whether ingest first reads the node table's B+tree files once, start to end, so
     * the page cache holds as much of them as fits before the random lookups begin.
     * Useful when the node table is larger than memory; off by default.
     */
    public static boolean PreloadNodeTable = false;

    /**
     * Whether parallel ingest ({@link #ingestThreads()} above 1) holds the node table's
     * hash to NodeId mapping in memory ({@link CompactNodeTable}), built at the start of
     * ingest by one sequential read of the B+tree, about 5-6 bytes a term. Lookups then
     * need no disk access; blank nodes and anything not found still use the B+tree.
     * Needs a heap that holds the table. Off by default.
     */
    public static boolean NodeTableInMemory = false;

    /** The thread count for the ingest step. */
    static int ingestThreads() {
        return IngestThreads > 0 ? IngestThreads : ParseThreads;
    }

    /**
     * Threads decoding the sorted node lines in the node table step's term index
     * ({@link SortedNodeRecords}); 1 (the default) is one decoder thread.
     */
    public static int TermThreads = 1;

    /** Size of the input chunks for {@link #ParseThreads} above 1. */
    public static int ParseChunkSize = 4 * 1024 * 1024;

    /**
     * Default sort program, found on the PATH.
     * It must accept the GNU sort(1) options used by xloader.
     */
    public static final String DefaultSortProgram = "sort";

    /*package*/ static String sortProgram(String sortProgram) {
        return ( sortProgram == null || sortProgram.isBlank() ) ? DefaultSortProgram : sortProgram;
    }

    /**
     * Program sort(1) uses to compress its temporary files, when compression is enabled.
     * It is run with no arguments to compress and with "-d" to decompress.
     * A null or blank program means {@link #gzipProgram()}.
     */
    /*package*/ static String sortCompressProgram(String sortCompressProgram) {
        return ( sortCompressProgram == null || sortCompressProgram.isBlank() ) ? gzipProgram() : sortCompressProgram;
    }

    /**
     * Whether a program can be run: a pathname that is an executable file,
     * or a name found as an executable file on the PATH.
     * Used to reject a missing --sort or --sort-compress program before a load starts,
     * rather than when sort(1) first needs it.
     */
    public static boolean programAvailable(String program) {
        if ( program.contains("/") )
            return isExecutableFile(Path.of(program));
        String searchPath = System.getenv("PATH");
        if ( searchPath == null )
            return false;
        for ( String dir : searchPath.split(File.pathSeparator) ) {
            if ( !dir.isEmpty() && isExecutableFile(Path.of(dir, program)) )
                return true;
        }
        return false;
    }

    private static boolean isExecutableFile(Path path) {
        return Files.isRegularFile(path) && Files.isExecutable(path);
    }

    // Ubuntu: it now (21.04) is at /usr/bin/gzip.
    //   /bin has become a symbolic link to /usr/bin.
    //   New installs of 20.04 have it at /usr/bin, upgrades have it at /bin.
    /*package*/ static String gzipProgram() {
        if ( programInstalledAt("/usr/bin/gzip") )
            return "/usr/bin/gzip";
        if ( programInstalledAt("/bin/gzip") )
            return "/bin/gzip";
        throw new TDBException("Can't find gzip program");
    }

    private static boolean programInstalledAt(String pathname) {
        Path path = Path.of(pathname);
        if ( ! Files.exists(path) )
            return false;
        if ( ! Files.isExecutable(path) )
            throw new TDBException(pathname+" is not executable by this process");
        return true;
    }

    public static Thread async(Runnable action, String threadName) {
        Objects.requireNonNull(action);
        Objects.requireNonNull(threadName);
        Thread thread = new Thread(action, threadName);
        thread.start();
        return thread;
    }

    public static void waitFor(Thread thread) {
        try { thread.join(); }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TDBException("Interrupted while waiting for " + thread.getName(), e);
        }
    }

    public static String rateStr(long items, long elapsedMillis) {
        double xSec = elapsedMillis/1000.0;
        double rate = items/xSec;
        return String.format("%,.0f", rate);
    }

    public static String milliToHMS(long milliSeconds) {
        long seconds = milliSeconds/1000;
        // Seconds to allocate
        long z = seconds;

        long h = z / 3600;
        z = z - (3600 * h);

        long m = z / 60;
        z = z - 60 * m;
        long s = z;
        //long check = 3600 * h + 60 * m + s;
        return String.format("%dh %02dm %02ds", h, m, s);
    }

    // Loggers

    public static Logger LOG_Data  = LoggerFactory.getLogger("Data");
    public static Logger LOG_Nodes = LoggerFactory.getLogger("Nodes");
    public static Logger LOG_Terms = LoggerFactory.getLogger("Terms");
    public static Logger LOG_Index = LoggerFactory.getLogger("Index");
}
