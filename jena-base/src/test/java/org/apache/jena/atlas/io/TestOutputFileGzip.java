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

package org.apache.jena.atlas.io;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.Deflater;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class TestOutputFileGzip {
    @TempDir Path directory;

    @Test public void levelApplied() throws IOException {
        // Level 0 stores the data, so the output is larger than the input.
        // Ignoring the level would give the default compression instead.
        byte[] data = "0123456789abcdef\n".repeat(1000).getBytes(StandardCharsets.US_ASCII);
        Path file = directory.resolve("stored.gz");
        try ( OutputStream out = IO.openOutputFile(file.toString(), Deflater.NO_COMPRESSION, 1024) ) {
            out.write(data);
        }
        assertTrue(Files.size(file) > data.length);
    }

    @Test public void badArguments() {
        String file = directory.resolve("bad.gz").toString();
        assertThrows(IllegalArgumentException.class, () -> IO.openOutputFileEx(file, 10, 512));
        assertThrows(IllegalArgumentException.class, () -> IO.openOutputFileEx(file, -2, 512));
        assertThrows(IllegalArgumentException.class, () -> IO.openOutputFileEx(file, 1, 0));
        assertFalse(Files.exists(Path.of(file)), "Checked before opening the file");
    }
}
