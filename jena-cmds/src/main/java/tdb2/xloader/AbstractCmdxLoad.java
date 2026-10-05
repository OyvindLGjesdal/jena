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

package tdb2.xloader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.jena.atlas.logging.LogCtl;
import org.apache.jena.cmd.ArgDecl;
import org.apache.jena.cmd.CmdException;
import org.apache.jena.cmd.CmdMain;
import org.apache.jena.sys.JenaSystem;
import org.apache.jena.tdb2.xloader.BulkLoaderX;
import org.apache.jena.tdb2.xloader.XLoaderFiles;

/**
 * Base class for TDB xloaders commands for java steps in the load process.
 * All steps accept all the same arguments, even if they are not applicable to the stage.
 */
abstract class AbstractCmdxLoad extends CmdMain {
    static {
        JenaSystem.init();
        LogCtl.setLog4j2();
    }
    // All possible arguments for xloader commands.
    // The commands themselves check whether they have the necessary arguments.
    protected static ArgDecl argLocation     = new ArgDecl(true, "location", "loc");
    protected static ArgDecl argTmpdir       = new ArgDecl(true, "tmpdir", "tmp");
    protected static ArgDecl argIndex        = new ArgDecl(true, "index");
    protected static ArgDecl argSortThreads  = new ArgDecl(true, "threads",  "thread", "sortThreads", "sortthreads");
    protected static ArgDecl argSortProgram  = new ArgDecl(true, "sort", "sortProgram", "sortprogram");
    protected static ArgDecl argSortCompress = new ArgDecl(true, "sort-compress", "sortCompress", "sortcompress");
    protected static ArgDecl argWorkfileGzipLevel  = new ArgDecl(true, "workfile-gzip-level");
    protected static ArgDecl argWorkfileGzipBuffer = new ArgDecl(true, "workfile-gzip-buffer");
    protected static ArgDecl argSortCompressNodes  = new ArgDecl(false, "sort-compress-nodes");
    protected static ArgDecl argSortBuffer   = new ArgDecl(true, "sort-buffer", "sortBuffer", "sortbuffer");
    protected static ArgDecl argParseThreads = new ArgDecl(true, "parse-threads", "parseThreads", "parsethreads");
    protected static ArgDecl argIngestThreads = new ArgDecl(true, "ingest-threads", "ingestThreads", "ingestthreads");
    protected static ArgDecl argPreloadNodeTable = new ArgDecl(false, "preload-node-table");
    protected static ArgDecl argNodeTableInMemory = new ArgDecl(false, "node-table-in-memory");
    protected static ArgDecl argTermThreads  = new ArgDecl(true, "term-threads", "termThreads", "termthreads");

//    // If this is put back, note there are two different sorts - one for the node table and several for the indexes.
//    protected static ArgDecl argSortNodeTableArgs   = new ArgDecl(true, "sortNodeTableArgs");
//    protected static ArgDecl argSortIndexArgs   = new ArgDecl(true, "sortIndexArgs");

    protected String location = null;
    protected String tmpdir = null;
    protected String indexName = null;

    protected int sortThreads = -1;

    // Executable used in place of sort(1); null means the default "sort" on the PATH.
    protected String sortProgram = null;
    // Compressor for sort's temporary files; null means gzip.
    protected String sortCompressProgram = null;

    // Gzip settings for the triples and quads workfiles written by the ingest step.
    protected int workfileGzipLevel = BulkLoaderX.WorkfileGzipLevel;
    protected int workfileGzipBufferSize = BulkLoaderX.WorkfileGzipBufferSize;

    // Whether the node table sort compresses its temporary files, as the index sorts do.
    protected boolean sortCompressNodes = BulkLoaderX.CompressSortNodeTableFiles;

    // If we add support for arguments to sort(1)
    protected String sortNodeTableArgs = null;
    protected String sortIndexArgs = null;

    protected List<String> filenames = null;

    protected XLoaderFiles loaderFiles = null;

    protected AbstractCmdxLoad(String stageName, String[] argv) {
        super(argv);
        setCmdArgs();

//        super.add(argLocation,     "--loc=", "Database location");
//        super.add(argTmpdir,       "--tmpdir=", "Temporary directory (defaults to --loc)");
//        super.add(argIndex,        "--index=", "Index name");
//        super.add(argSortThreads,  "--threads=", "Number of threads; passed as an argument to sort(1)");
//        super.add(argSortArgs,     "--sortArgs=", "Arguments to sort(1)");
    }

    protected abstract void setCmdArgs();

    protected String getArgsSummary() {
        return "--loc=DIR --tmpdir=DIR";
    }

    @Override
    protected void processModulesAndArgs() {
        if ( ! super.hasArg(argLocation) )
            throw new CmdException("Required: --loc=");

        location = super.getValue(argLocation);
        tmpdir = super.getValue(argTmpdir);
        indexName = super.getValue(argIndex);

        if ( super.contains(argSortProgram) ) {
            sortProgram = super.getValue(argSortProgram);
            if ( sortProgram == null || sortProgram.isBlank() )
                throw new CmdException("--sort :: No sort program given");
            if ( ! BulkLoaderX.programAvailable(sortProgram) )
                throw new CmdException("--sort :: Program not found or not executable: "+sortProgram);
        }
        if ( super.contains(argSortCompress) ) {
            sortCompressProgram = super.getValue(argSortCompress);
            if ( sortCompressProgram == null || sortCompressProgram.isBlank() )
                throw new CmdException("--sort-compress :: No compress program given");
            // Otherwise this would only fail when an index sort first spills to disk.
            if ( ! BulkLoaderX.programAvailable(sortCompressProgram) )
                throw new CmdException("--sort-compress :: Program not found or not executable: "+sortCompressProgram);
        }
        if ( super.contains(argWorkfileGzipLevel) ) {
            workfileGzipLevel = intArg(argWorkfileGzipLevel, "--workfile-gzip-level");
            if ( workfileGzipLevel < -1 || workfileGzipLevel > 9 )
                throw new CmdException("--workfile-gzip-level :: Must be -1 (Java default) or 0 to 9: "+workfileGzipLevel);
        }
        if ( super.contains(argSortCompressNodes) )
            sortCompressNodes = true;
        if ( super.contains(argParseThreads) ) {
            int threads = intArg(argParseThreads, "--parse-threads");
            if ( threads < 1 || threads > 256 )
                throw new CmdException("--parse-threads :: Must be 1 to 256: "+threads);
            // Each xloader step runs in its own JVM.
            BulkLoaderX.ParseThreads = threads;
        }
        if ( super.contains(argTermThreads) ) {
            int threads = intArg(argTermThreads, "--term-threads");
            if ( threads < 1 || threads > 256 )
                throw new CmdException("--term-threads :: Must be 1 to 256: "+threads);
            BulkLoaderX.TermThreads = threads;
        }
        if ( super.contains(argPreloadNodeTable) )
            BulkLoaderX.PreloadNodeTable = true;
        if ( super.contains(argNodeTableInMemory) )
            BulkLoaderX.NodeTableInMemory = true;
        if ( super.contains(argIngestThreads) ) {
            int threads = intArg(argIngestThreads, "--ingest-threads");
            if ( threads < 1 || threads > 1024 )
                throw new CmdException("--ingest-threads :: Must be 1 to 1024: "+threads);
            BulkLoaderX.IngestThreads = threads;
        }
        if ( super.contains(argSortBuffer) ) {
            String bufferSize = super.getValue(argSortBuffer);
            if ( !BulkLoaderX.isSortBufferSize(bufferSize) )
                throw new CmdException("--sort-buffer :: Expected a size such as 50%, 4G or 1024M: "+bufferSize);
            // Each xloader step runs in its own JVM.
            BulkLoaderX.SortBufferSize = bufferSize;
        }
        if ( super.contains(argWorkfileGzipBuffer) ) {
            workfileGzipBufferSize = intArg(argWorkfileGzipBuffer, "--workfile-gzip-buffer");
            if ( workfileGzipBufferSize <= 0 )
                throw new CmdException("--workfile-gzip-buffer :: Must be a positive number of bytes: "+workfileGzipBufferSize);
        }

//        sortNodeTableArgs = super.getValue(argSortNodeTableArgs);
//        sortIndexArgs = super.getValue(argSortIndexArgs);

        if ( location != null )
            checkDirectory(location);
        if ( tmpdir != null )
            checkDirectory(tmpdir);
        else
            tmpdir = location;
        filenames = new ArrayList<>(super.getPositional());

        if ( super.contains(argSortThreads) ) {
            String str = super.getValue(argSortThreads);
            try {
                sortThreads = Integer.parseInt(str);
            } catch (NumberFormatException ex) {
                throw new CmdException("--threads :: Failed to parse '"+str+"' as an integer");
            }
        }

        subCheckArgs();

        loaderFiles = new XLoaderFiles(tmpdir);
    }

    private int intArg(ArgDecl arg, String name) {
        String str = super.getValue(arg);
        try {
            return Integer.parseInt(str);
        } catch (NumberFormatException ex) {
            throw new CmdException(name+" :: Failed to parse '"+str+"' as an integer");
        }
    }

    private void checkDirectory(String dirname) {
        try {
            Path path = Paths.get(dirname);
            if ( Files.exists(path) )
                path = path.toRealPath();
            if ( Files.exists(path) ) {
                if ( !Files.isDirectory(path) || !Files.isWritable(path) ) {
                    throw new CmdException("Path name '" + dirname + "' exists but is not a writable directory");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    protected abstract void subCheckArgs();
}
