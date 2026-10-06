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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.zip.GZIPOutputStream;

import org.apache.jena.tdb2.TDBException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class TestSharedWorkfileReader {
    @TempDir Path directory;

    /** A compressed workfile of rows, as ingest writes them. */
    private byte[] workfile(Path file, int rows) throws IOException {
        StringBuilder sb = new StringBuilder();
        for ( int i = 0 ; i < rows ; i++ )
            sb.append(String.format("%016X %016X %016X\n", i, i * 7L, i * 13L));
        byte[] bytes = sb.toString().getBytes(StandardCharsets.US_ASCII);
        try ( OutputStream out = new GZIPOutputStream(Files.newOutputStream(file)) ) {
            out.write(bytes);
        }
        return bytes;
    }

    @Test
    public void everySortGetsTheWholeFile() {
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            Path file = directory.resolve("triples.tmp.gz");
            byte[] expected = workfile(file, 10_000);
            ExecutorService pool = Executors.newFixedThreadPool(3);
            // Small blocks and queues: the reader waits for the slowest sort many times.
            try ( SharedWorkfileReader reader = new SharedWorkfileReader(file.toString(), 3, 1000, 4) ) {
                List<Future<byte[]>> results = new ArrayList<>();
                for ( int i = 0 ; i < 3 ; i++ ) {
                    SortProcess.Producer producer = reader.producer();
                    results.add(pool.submit(() -> {
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        producer.write(out);
                        return out.toByteArray();
                    }));
                }
                for ( Future<byte[]> result : results )
                    assertArrayEquals(expected, result.get());
                assertThrows(IllegalStateException.class, reader::producer, "Only one producer per sort");
            } finally {
                pool.shutdownNow();
            }
        });
    }

    @Test
    public void failureStopsTheOtherSorts() {
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            Path file = directory.resolve("quads.tmp.gz");
            workfile(file, 10_000);
            ExecutorService pool = Executors.newFixedThreadPool(2);
            try ( SharedWorkfileReader reader = new SharedWorkfileReader(file.toString(), 2, 1000, 4) ) {
                SortProcess.Producer failing = reader.producer();
                SortProcess.Producer other = reader.producer();
                // Like a sort that has exited: its stdin fails after the first write.
                IOException brokenPipe = new IOException("Broken pipe");
                Future<?> f1 = pool.submit(() -> {
                    failing.write(new OutputStream() {
                        int writes = 0;
                        @Override public void write(int b) throws IOException { write(new byte[] {(byte)b}, 0, 1); }
                        @Override public void write(byte[] b, int off, int len) throws IOException {
                            if ( ++writes > 1 )
                                throw brokenPipe;
                        }
                    });
                    return null;
                });
                Future<?> f2 = pool.submit(() -> { other.write(OutputStream.nullOutputStream()); return null; });
                Exception ex1 = assertThrows(Exception.class, f1::get);
                assertSame(brokenPipe, ex1.getCause());
                // The other sort's input fails too, instead of waiting for blocks that never come.
                Exception ex2 = assertThrows(Exception.class, f2::get);
                assertInstanceOf(TDBException.class, ex2.getCause());
                assertSame(brokenPipe, ex2.getCause().getCause());
            } finally {
                pool.shutdownNow();
            }
        });
    }

    @Test
    public void closeStopsWaitingReader() {
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            Path file = directory.resolve("triples.tmp.gz");
            workfile(file, 10_000);
            // No sort reads: the reader fills the queues and waits until closed.
            SharedWorkfileReader reader = new SharedWorkfileReader(file.toString(), 2, 1000, 4);
            Thread.sleep(200);
            reader.close();
            SortProcess.Producer late = reader.producer();
            assertThrows(TDBException.class, () -> late.write(OutputStream.nullOutputStream()));
        });
    }
}
