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

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.options.ChainedOptionsBuilder;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

/** Input file and default JMH options for the xloader benchmarks. */
class XLoaderJmh {

    /** Environment variable naming the RDF file to read, for example a {@code .nt.gz} file. */
    static final String DATA_ENV = "XLOADER_JMH_DATA";

    static String dataFile() {
        String datafile = System.getenv(DATA_ENV);
        if ( datafile == null || datafile.isBlank() )
            throw new IllegalStateException("Set " + DATA_ENV + " to the RDF file to parse, for example a .nt.gz file");
        if ( !Files.isRegularFile(Path.of(datafile)) )
            throw new IllegalStateException(DATA_ENV + ": not a file: " + datafile);
        return datafile;
    }

    static ChainedOptionsBuilder options(Class<?> c) {
        // XLOADER_JMH_INCLUDE: optional regular expression for benchmark method names.
        String methods = System.getenv("XLOADER_JMH_INCLUDE");
        String include = c.getName() + (methods == null || methods.isBlank() ? "" : "\\.(" + methods + ")$");
        return new OptionsBuilder()
                .include(include)
                // Each invocation is one whole pass over the file.
                .mode(Mode.SingleShotTime)
                .timeUnit(TimeUnit.SECONDS)
                .warmupIterations(1)
                .measurementIterations(3)
                .measurementTime(TimeValue.NONE)
                .threads(1)
                .forks(1)
                .shouldFailOnError(true)
                .shouldDoGC(true)
                // As tdb2.xloader
                .jvmArgs("-Xmx4G")
                .resultFormat(ResultFormatType.JSON)
                .result(c.getSimpleName() + "_"
                        + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss")) + ".json");
    }
}
