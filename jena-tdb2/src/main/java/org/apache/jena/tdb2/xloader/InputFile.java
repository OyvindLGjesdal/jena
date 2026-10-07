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

import java.io.InputStream;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFLanguages;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.riot.RDFParserBuilder;

/**
 * An input file for the node table and ingest steps: parsed with RIOT as usual, or read
 * as decompressed bytes for {@link ParallelParser}.
 */
final class InputFile implements AutoCloseable {
    private final String datafile;
    private InputStream opened = null;

    private InputFile(String datafile) {
        this.datafile = datafile;
    }

    static InputFile open(String datafile) {
        return new InputFile(datafile);
    }

    /**
     * The RDF language for a data file's name, ignoring a compression extension such as
     * {@code .gz} (as RIOT does); null if none.
     */
    static Lang lang(String datafile) {
        return RDFLanguages.filenameToLang(datafile);
    }

    /**
     * The decompressed bytes of this file, opened as RIOT opens it (a {@code .gz} file
     * through Java's gzip). Closed by {@link #close}.
     */
    InputStream stream() {
        if ( opened == null )
            opened = IO.openFile(datafile);
        return opened;
    }

    /** The parser for this file. */
    RDFParserBuilder parser() {
        return RDFParser.source(datafile);
    }

    @Override
    public void close() {
        if ( opened != null )
            IO.close(opened);
    }
}
