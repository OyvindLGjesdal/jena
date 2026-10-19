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

package org.apache.jena.sparql.expr;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.options.ChainedOptionsBuilder;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

/**
 * Reads the string samples written by {@code scripts/extract_lexeme_strings.py}
 * ({@code name.bin}, or gzipped as {@code name.bin.gz}). The directory is given by the
 * system property {@value #PROPERTY}, by default {@value #DEFAULT_DIR} in this module.
 */
public final class StringCompareData {
    public static final String PROPERTY = "jena.strcmp.data";
    public static final String DEFAULT_DIR = "data/strcmp";

    private StringCompareData() {}

    /** The data directory as an absolute path, or null if there is none. */
    public static String directory() {
        String dir = System.getProperty(PROPERTY);
        if ( dir == null && Files.isDirectory(Path.of(DEFAULT_DIR)) )
            dir = DEFAULT_DIR;
        return dir == null ? null : Path.of(dir).toAbsolutePath().toString();
    }

    /**
     * Options used for the GH-4300 runs: 2 forks, 3 x 1s warmup, 5 x 1s measurement.
     * Time units come from the benchmark annotations. The data directory is passed on to the forks.
     */
    public static ChainedOptionsBuilder options(Class<?> c) {
        return new OptionsBuilder()
                .include(c.getName())
                .mode(Mode.AverageTime)
                .forks(2)
                .warmupIterations(3)
                .warmupTime(TimeValue.seconds(1))
                .measurementIterations(5)
                .measurementTime(TimeValue.seconds(1))
                .threads(1)
                .shouldFailOnError(true)
                .jvmArgsAppend("-Xms3g", "-Xmx3g", "-D" + PROPERTY + "=" + directory())
                .resultFormat(ResultFormatType.JSON)
                .result(c.getSimpleName() + "_" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss")) + ".json");
    }

    /** Format per string: 4-byte big-endian length in UTF-16 units, then UTF-16BE chars. */
    public static String[] load(String name) throws IOException {
        String dir = directory();
        if ( dir == null )
            throw new IllegalStateException("Set -D" + PROPERTY + "=<directory with literals.bin, langlits.bin, iris.bin>");
        Path gz = Path.of(dir, name + ".bin.gz");
        InputStream raw = Files.exists(gz)
            ? new GZIPInputStream(Files.newInputStream(gz), 1 << 16)
            : Files.newInputStream(Path.of(dir, name + ".bin"));
        List<String> list = new ArrayList<>();
        try ( DataInputStream in = new DataInputStream(new BufferedInputStream(raw, 1 << 16)) ) {
            while ( true ) {
                int n;
                try {
                    n = in.readInt();
                } catch (EOFException ex) {
                    break;
                }
                char[] chars = new char[n];
                for ( int i = 0 ; i < n ; i++ )
                    chars[i] = in.readChar();
                // new String(char[]) uses compact strings (LATIN1 when possible), as parsed data does.
                list.add(new String(chars));
            }
        }
        return list.toArray(new String[0]);
    }
}
