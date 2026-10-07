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
import java.io.Reader;

import org.junit.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.atlas.io.PeekReader;

/**
 * Reading the input the way the parser does, without parsing: how much of a parse
 * pass ({@link TestXLoaderParse}) is decompression and character decoding.
 * <p>
 * Each invocation reads the whole file named by the environment variable
 * {@code XLOADER_JMH_DATA}, opened with {@link IO#openFile} as RIOT does
 * (a {@code .gz} file through {@code GZIPInputStream}).
 * <ul>
 * <li>{@code inflate}: bytes only, in 64 KB blocks.</li>
 * <li>{@code inflateUtf8}: decoded to characters by {@link IO#asUTF8}, in 64 K blocks.</li>
 * <li>{@code peekReader}: one character at a time through
 * {@link PeekReader#makeUTF8}, the tokenizer's input.</li>
 * </ul>
 */
@State(Scope.Benchmark)
public class TestXLoaderRead {

    private String datafile;

    @Setup(Level.Trial)
    public void setup() {
        datafile = XLoaderJmh.dataFile();
    }

    @Benchmark
    public long inflate() throws IOException {
        long count = 0;
        byte[] buffer = new byte[64 * 1024];
        try ( InputStream in = IO.openFile(datafile) ) {
            int n;
            while ( (n = in.read(buffer)) != -1 )
                count += n;
        }
        return count;
    }

    @Benchmark
    public long inflateUtf8() throws IOException {
        long count = 0;
        char[] buffer = new char[64 * 1024];
        try ( Reader in = IO.asUTF8(IO.openFile(datafile)) ) {
            int n;
            while ( (n = in.read(buffer)) != -1 )
                count += n;
        }
        return count;
    }

    @Benchmark
    public long peekReader() throws IOException {
        long count = 0;
        try ( PeekReader in = PeekReader.makeUTF8(IO.openFile(datafile)) ) {
            while ( in.readChar() != IO.EOF )
                count++;
        }
        return count;
    }

    @Test
    public void benchmark() throws Exception {
        // Fail here, before JMH forks, if the data file is missing.
        XLoaderJmh.dataFile();
        new Runner(XLoaderJmh.options(TestXLoaderRead.class).build()).run();
    }
}
