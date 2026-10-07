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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

import org.apache.jena.graph.NodeFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.riot.RiotParseException;
import org.apache.jena.riot.thrift.ThriftConvert;
import org.apache.jena.tdb2.TDBException;
import org.apache.thrift.TSerializer;
import org.apache.thrift.protocol.TCompactProtocol;
import org.junit.jupiter.api.Test;

public class TestParallelNodeParser {

    /** N-Triples with repeated terms, literals of several kinds and blank nodes in many lines. */
    private static String data(int lines, int blankNodes) {
        StringBuilder sb = new StringBuilder();
        for ( int i = 0 ; i < lines ; i++ ) {
            switch ( i % 5 ) {
                case 0 -> sb.append("<urn:s").append(i / 10).append("> <urn:p").append(i % 7)
                        .append("> <urn:o").append(i).append("> .\n");
                case 1 -> sb.append("<urn:s").append(i / 10).append("> <urn:label> \"label ").append(i)
                        .append("\"@en .\n");
                case 2 -> sb.append("<urn:s").append(i / 10).append("> <urn:n> \"").append(i)
                        .append("\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n");
                case 3 -> sb.append("_:b").append(i % blankNodes).append(" <urn:p> \"esc\\\"aped \\u00E9 ").append(i)
                        .append("\" .\n");
                default -> sb.append("<urn:s").append(i / 10).append("> <urn:unknown> _:b").append(i % blankNodes)
                        .append(" .\n");
            }
        }
        return sb.toString();
    }

    private record Result(Set<String> lines, long count) {}

    private static Result parallel(String data, Lang lang, int threads, int chunkSize) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        AtomicLong progress = new AtomicLong();
        long count = ParallelNodeParser.parse(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), lang,
                                              "file:///test", java.util.UUID.randomUUID(), out, threads, chunkSize,
                                              () -> false, progress::addAndGet);
        assertEquals(count, progress.get(), "Progress reports every statement");
        return new Result(lines(out), count);
    }

    private static Result sequential(String data, Lang lang) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        var stream = new ProcBuildNodeTableX.NodeHashTmpStream(out);
        long[] count = new long[1];
        RDFParser.fromString(data, lang).parse(new org.apache.jena.riot.system.StreamRDFWrapper(stream) {
            @Override public void triple(org.apache.jena.graph.Triple t) { count[0]++; super.triple(t); }
            @Override public void quad(org.apache.jena.sparql.core.Quad q) { count[0]++; super.quad(q); }
        });
        stream.finish();
        return new Result(lines(out), count[0]);
    }

    /** Distinct blank node labels in the data. */
    private static long labels(String data) {
        return java.util.regex.Pattern.compile("_:b[0-9]+").matcher(data).results()
                .map(m -> m.group()).distinct().count();
    }

    private static Set<String> lines(ByteArrayOutputStream out) {
        return new HashSet<>(out.toString(StandardCharsets.UTF_8).lines().toList());
    }

    private static final String BLANK_PREFIX = blankPrefix();

    private static String blankPrefix() {
        try {
            byte[] b = new TSerializer(new TCompactProtocol.Factory())
                    .serialize(ThriftConvert.convert(NodeFactory.createBlankNode(), false));
            return String.format("%02X", b[0] & 0xFF);
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static boolean isBlank(String line) {
        return line.substring(line.indexOf(' ') + 1).startsWith(BLANK_PREFIX);
    }

    private static Set<String> withoutBlankNodes(Set<String> lines) {
        Set<String> x = new HashSet<>(lines);
        x.removeIf(TestParallelNodeParser::isBlank);
        return x;
    }

    private static long blankNodes(Set<String> lines) {
        return lines.stream().filter(TestParallelNodeParser::isBlank).count();
    }

    @Test
    public void sameNodesAsOneThread() {
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            String data = data(5_000, 40);
            Result expected = sequential(data, Lang.NTRIPLES);
            // Small chunks: many chunks, each blank node label in many of them.
            Result actual = parallel(data, Lang.NTRIPLES, 4, 512);
            assertEquals(expected.count(), actual.count());
            assertEquals(withoutBlankNodes(expected.lines()), withoutBlankNodes(actual.lines()));
            // One node per blank node label across all chunks.
            long labels = labels(data);
            assertTrue(labels > 10, "Test data has many labels");
            assertEquals(labels, blankNodes(actual.lines()));
            assertEquals(labels, blankNodes(expected.lines()));
        });
    }

    @Test
    public void oneThread() {
        String data = data(500, 5);
        Result expected = sequential(data, Lang.NTRIPLES);
        Result actual = parallel(data, Lang.NTRIPLES, 1, 256);
        assertEquals(withoutBlankNodes(expected.lines()), withoutBlankNodes(actual.lines()));
        assertEquals(labels(data), blankNodes(actual.lines()));
    }

    @Test
    public void parseErrorReportsLineInInput() {
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            String[] lines = data(1_000, 5).split("\n");
            lines[776] = "<urn:s> <urn:p> not RDF";
            String data = String.join("\n", lines) + "\n";
            RiotParseException ex = assertThrows(RiotParseException.class, () -> parallel(data, Lang.NTRIPLES, 4, 300));
            assertEquals(777, ex.getLine(), ex.getMessage());
        });
    }

    @Test
    public void lineLongerThanChunk() {
        String longLiteral = "x".repeat(5_000);
        String data = "<urn:s> <urn:p> \"" + longLiteral + "\" .\n" + data(200, 3);
        Result expected = sequential(data, Lang.NTRIPLES);
        Result actual = parallel(data, Lang.NTRIPLES, 3, 64);
        assertEquals(expected.count(), actual.count());
        assertEquals(withoutBlankNodes(expected.lines()), withoutBlankNodes(actual.lines()));
    }

    @Test
    public void sharedOrPerWorkerCache() {
        // The default size, and caches far smaller than the number of nodes (250 entries
        // per worker), which write many nodes more than once.
        String data = data(5_000, 40);
        Set<String> expected = withoutBlankNodes(sequential(data, Lang.NTRIPLES).lines());
        boolean saved = ParallelNodeParser.SharedCache;
        int savedSize = ParallelNodeParser.CacheSize;
        try {
            for ( int size : new int[] {0, 1000} ) {
                for ( boolean shared : new boolean[] {true, false} ) {
                    String what = "shared=" + shared + ", size=" + size;
                    ParallelNodeParser.SharedCache = shared;
                    ParallelNodeParser.CacheSize = size;
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    LongAdder lines = new LongAdder();
                    ParallelNodeParser.parse(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)),
                            Lang.NTRIPLES, "file:///test", java.util.UUID.randomUUID(), out, 4, 256,
                            () -> false, n -> {}, lines);
                    assertEquals(out.toString(StandardCharsets.UTF_8).lines().count(), lines.sum(),
                            "Lines counted, " + what);
                    assertEquals(expected, withoutBlankNodes(lines(out)), what);
                }
            }
        } finally {
            ParallelNodeParser.SharedCache = saved;
            ParallelNodeParser.CacheSize = savedSize;
        }
    }

    @Test
    public void cacheSizes() {
        assertEquals(3_000_000, ParallelNodeParser.cacheSize(null));
        assertEquals(2_000_000, ParallelNodeParser.cacheSize("2_000_000"));
        assertThrows(TDBException.class, () -> ParallelNodeParser.cacheSize("3M"));
        assertThrows(TDBException.class, () -> ParallelNodeParser.cacheSize("10"));
        // At most 500,000 each, as on one thread; more workers share the total.
        assertEquals(500_000, ParallelNodeParser.workerCacheSize(3_000_000, 2));
        assertEquals(500_000, ParallelNodeParser.workerCacheSize(3_000_000, 6));
        assertEquals(250_000, ParallelNodeParser.workerCacheSize(3_000_000, 12));
        assertEquals(93_750, ParallelNodeParser.workerCacheSize(3_000_000, 32));
    }

    @Test
    public void chunksAfterLongLineAreChunkSize() {
        // A line much longer than the chunk, then short lines of 26 bytes: a 256 byte
        // chunk holds at most 9 of them. Only the chunk with the long line is larger.
        String shortLine = "<urn:s> <urn:p> <urn:o> .\n";
        String data = "<urn:s> <urn:p> \"" + "x".repeat(100_000) + "\" .\n" + shortLine.repeat(10_000);
        List<Long> perChunk = Collections.synchronizedList(new ArrayList<>());
        long count = ParallelNodeParser.parse(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)),
                Lang.NTRIPLES, "file:///test", java.util.UUID.randomUUID(), new ByteArrayOutputStream(), 2, 256,
                () -> false, perChunk::add);
        assertEquals(10_001, count);
        long large = perChunk.stream().filter(n -> n > 256 / shortLine.length()).count();
        assertEquals(1, large, "Chunks larger than the chunk size");
    }

    @Test
    public void noFinalNewline() {
        String data = data(100, 3) + "<urn:last> <urn:p> <urn:o> .";
        Result actual = parallel(data, Lang.NTRIPLES, 2, 128);
        assertEquals(101, actual.count());
        assertEquals(withoutBlankNodes(sequential(data, Lang.NTRIPLES).lines()), withoutBlankNodes(actual.lines()));
    }

    @Test
    public void emptyInput() {
        assertEquals(0, parallel("", Lang.NTRIPLES, 4, 128).count());
    }

    @Test
    public void quads() {
        StringBuilder sb = new StringBuilder();
        for ( int i = 0 ; i < 1_000 ; i++ ) {
            sb.append("<urn:s").append(i % 13).append("> <urn:p> \"v").append(i)
                    .append("\" <urn:g").append(i % 3).append("> .\n");
        }
        String data = sb.toString();
        Result expected = sequential(data, Lang.NQUADS);
        Result actual = parallel(data, Lang.NQUADS, 4, 200);
        assertEquals(1_000, actual.count());
        assertEquals(expected.lines(), actual.lines());
    }
}
