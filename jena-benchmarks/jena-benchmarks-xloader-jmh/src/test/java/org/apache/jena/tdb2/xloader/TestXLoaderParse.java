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

import java.io.OutputStream;
import java.util.List;

import org.junit.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.riot.RDFParserBuilder;
import org.apache.jena.riot.system.AsyncParser;
import org.apache.jena.riot.system.StreamRDF;
import org.apache.jena.riot.system.StreamRDFBase;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.graph.Triple;

/**
 * The parse step of the xloader node table stage, without the external sort.
 * <p>
 * Each invocation parses the whole file named by the environment variable
 * {@code XLOADER_JMH_DATA}, for example a {@code .nt.gz} file.
 * <ul>
 * <li>{@code parse}, {@code parseAsync}: parsing only, into a counting stream.</li>
 * <li>{@code nodeTable}, {@code nodeTableAsync}: parsing into the node table stage's
 * {@link ProcBuildNodeTableX.NodeHashTmpStream} (cache, hash, Thrift, hex),
 * writing to a buffered null output stream instead of {@code sort}.</li>
 * </ul>
 * The synchronous variants are what xloader does now; the async variants parse on a
 * separate thread with {@link AsyncParser}.
 */
@State(Scope.Benchmark)
public class TestXLoaderParse {

    @Param({"true", "false"})
    public boolean checking;

    private String datafile;

    @Setup(Level.Trial)
    public void setup() {
        datafile = XLoaderJmh.dataFile();
    }

    private RDFParserBuilder source() {
        return RDFParser.source(datafile).checking(checking);
    }

    @Benchmark
    public long parse() {
        CountingStream counter = new CountingStream();
        parse(counter);
        return counter.count;
    }

    @Benchmark
    public long parseAsync() {
        CountingStream counter = new CountingStream();
        parseAsync(counter);
        return counter.count;
    }

    @Benchmark
    public void nodeTable() {
        OutputStream output = IO.ensureBuffered(OutputStream.nullOutputStream());
        parse(new ProcBuildNodeTableX.NodeHashTmpStream(output));
    }

    @Benchmark
    public void nodeTableAsync() {
        OutputStream output = IO.ensureBuffered(OutputStream.nullOutputStream());
        parseAsync(new ProcBuildNodeTableX.NodeHashTmpStream(output));
    }

    private void parse(StreamRDF stream) {
        stream.start();
        source().parse(stream);
        stream.finish();
    }

    private void parseAsync(StreamRDF stream) {
        stream.start();
        AsyncParser.asyncParseSources(List.of(source()), stream);
        stream.finish();
    }

    private static class CountingStream extends StreamRDFBase {
        long count = 0;

        @Override
        public void triple(Triple triple) { count++; }

        @Override
        public void quad(Quad quad) { count++; }
    }

    @Test
    public void benchmark() throws Exception {
        // Fail here, before JMH forks, if the data file is missing.
        XLoaderJmh.dataFile();
        new Runner(XLoaderJmh.options(TestXLoaderParse.class).build()).run();
    }
}
