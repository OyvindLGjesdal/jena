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

import org.apache.jena.atlas.lib.FileOps;
import org.apache.jena.cmd.CmdException;
import org.apache.jena.tdb2.xloader.BulkLoaderX;
import org.apache.jena.tdb2.xloader.ProcBuildNodeTableX;

public class CmdxBuildNodeTable extends AbstractCmdxLoad {

    public static void main(String... args) {
        new CmdxBuildNodeTable(args).mainRun();
    }

    protected CmdxBuildNodeTable(String[] argv) {
        super("Nodes", argv);
    }

    @Override
    protected void setCmdArgs() {
        super.add(argLocation,      "--loc=", "Database location");
        super.add(argTmpdir,        "--tmpdir=", "Temporary directory (defaults to --loc)");
        super.add(argSortThreads,   "--threads=", "Number of threads; passed as an argument to sort(1)");
        super.add(argSortProgram,   "--sort=", "Sort program (default: sort on the PATH); must accept the GNU sort(1) options used by xloader");
        super.add(argSortCompress,  "--sort-compress=", "Program sort(1) uses to compress its temporary files (default: gzip); run with no arguments and with -d");
        super.add(argSortCompressNodes, "--sort-compress-nodes", "Compress the node table sort's temporary files too (default: only the index sorts)");
        super.add(argSortBuffer,    "--sort-buffer=", "Size for sort's --buffer-size (default: 50%)");
        super.add(argParseThreads,  "--parse-threads=", "Threads parsing N-Triples/N-Quads input (default: 1)");
        super.add(argTermThreads,   "--term-threads=", "Threads decoding the sorted nodes for the term index (default: 1)");
        //super.add(argSortNodeTableArgs, "--sortNodeTableArgs=", "Specialised argument for the sort for the node table");
    }

    @Override
    protected String getSummary() {
        return getCommandName()+" "+getArgsSummary();
    }

    @Override
    protected void subCheckArgs() {
        if ( location == null )
            throw new CmdException("Required : --loc");
        if ( filenames.isEmpty() )
            throw new CmdException("No files to load");
    }

    @Override
    protected String getCommandName() {
        return this.getClass().getCanonicalName();
    }

    @Override
    protected void exec() {
        FileOps.ensureDir(location);
        // Deletes any existing database!
        FileOps.clearAll(location);

        if ( tmpdir == null )
            tmpdir = location;
        // Each xloader stage runs in its own JVM, so setting the switch here affects only this load.
        BulkLoaderX.CompressSortNodeTableFiles = sortCompressNodes;
        ProcBuildNodeTableX.exec(location, loaderFiles, sortProgram, sortCompressProgram, sortThreads, sortNodeTableArgs, filenames);
    }
}
