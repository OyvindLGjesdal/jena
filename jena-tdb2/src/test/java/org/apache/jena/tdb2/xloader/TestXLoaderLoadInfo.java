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

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.atlas.json.JSON;
import org.apache.jena.atlas.json.JsonObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * "tdb2.xloader: default-graph N-Quads/TriG statements are counted as quads, so the
 * triple indexes are skipped".
 * <p>
 * Ingest writes statements in the default graph of N-Quads or TriG input to the triples
 * workfile, and must count them as triples: when load.json reports {@code "triples":0},
 * tdb2.xloader builds none of SPO, POS, OSP, and the default graph is empty.
 * The test uses the ingest step alone (ingest allocates the nodes itself), so it does
 * not need GNU sort, and it compiles against main.
 */
public class TestXLoaderLoadInfo {
    @TempDir Path directory;

    @Test
    public void defaultGraphNQuadsCountedAsTriples() throws Exception {
        assertCounts("data.nq", """
                <urn:s> <urn:p> <urn:o1> .
                <urn:s> <urn:p> <urn:o2> .
                <urn:s> <urn:p> <urn:o3> <urn:g> .
                """);
    }

    @Test
    public void defaultGraphTriGCountedAsTriples() throws Exception {
        // LangTriG sends the default graph to the stream as quads.
        assertCounts("data.trig", """
                <urn:s> <urn:p> <urn:o1> .
                { <urn:s> <urn:p> <urn:o2> }
                <urn:g> { <urn:s> <urn:p> <urn:o3> }
                """);
    }

    /** Ingest {@code data}: two statements in the default graph and one in a named graph. */
    private void assertCounts(String filename, String data) throws Exception {
        Path input = directory.resolve(filename);
        Files.writeString(input, data);
        XLoaderFiles files = new XLoaderFiles(Files.createDirectory(directory.resolve("tmp")).toString());
        ProcIngestDataX.exec(directory.resolve("db").toString(), files, List.of(input.toString()), false);

        // The workfiles are right: two default-graph rows for SPO/POS/OSP, one named-graph row.
        assertEquals(2, rows(files.triplesFile));
        assertEquals(1, rows(files.quadsFile));

        // load.json should agree: tdb2.xloader skips the triple indexes when "triples" is 0.
        JsonObject info = JSON.read(files.loadInfo);
        assertEquals(2, info.get("triples").getAsNumber().value().longValue(), "triples in " + info);
        assertEquals(1, info.get("quads").getAsNumber().value().longValue(), "quads in " + info);
    }

    /** Rows in a workfile, compressed or not. */
    private static long rows(String filename) throws IOException {
        try ( BufferedReader reader = new BufferedReader(new InputStreamReader(IO.openFile(filename), StandardCharsets.US_ASCII)) ) {
            return reader.lines().filter(line -> !line.isEmpty()).count();
        }
    }
}
