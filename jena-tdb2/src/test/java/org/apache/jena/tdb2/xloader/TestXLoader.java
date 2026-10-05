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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.zip.Deflater;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.apache.jena.atlas.iterator.Iter;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.atlas.lib.FileOps;
import org.apache.jena.graph.Graph;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.graph.Triple;
import org.apache.jena.riot.RiotException;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.tdb2.DatabaseMgr;
import org.apache.jena.tdb2.TDBException;
import org.apache.jena.tdb2.sys.TDBInternal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class TestXLoader {
    @TempDir Path directory;

    private XLoaderFiles files() throws IOException {
        return new XLoaderFiles(Files.createDirectory(directory.resolve("tmp")).toString());
    }

    private Path rdf(String contents, String extension) throws IOException {
        Path input = directory.resolve("input." + extension);
        Files.writeString(input, contents);
        return input;
    }

    private String database() { return directory.resolve("db").toString(); }

    private static void requireSort() throws Exception {
        Process process;
        try {
            process = new ProcessBuilder("sort", "--version").start();
        } catch (IOException ex) {
            assumeTrue(false, "GNU sort is required for xloader integration tests");
            return;
        }
        try {
            assertTrue(process.waitFor(5, TimeUnit.SECONDS));
            String version = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assumeTrue(process.exitValue() == 0 && version.contains("GNU coreutils"), "GNU sort required");
        } finally {
            process.destroyForcibly();
            process.getInputStream().close();
            process.getErrorStream().close();
            process.getOutputStream().close();
        }
    }

    @Test
    public void loadTriplesAndQuads() throws Exception {
        requireSort();
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            XLoaderFiles files = files();
            Path input = rdf("<urn:s1> <urn:p> <urn:o1> .\n"
                    + "<urn:s1> <urn:p> <urn:o1> .\n"
                    + "<urn:s2> <urn:p> <urn:o2> .\n"
                    + "<urn:s3> <urn:p> <urn:o3> <urn:g> .\n", "nq");
            List<String> inputs = List.of(input.toString());
            ProcBuildNodeTableX.exec(database(), files, 2, null, inputs);
            ProcIngestDataX.exec(database(), files, inputs, false);
            for ( String index : List.of("SPO", "POS", "OSP", "GSPO", "GPOS", "GOSP", "SPOG", "POSG", "OSPG") )
                ProcBuildIndexX.exec(database(), index, 2, null, files);
            var dsg = DatabaseMgr.connectDatasetGraph(database());
            try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
                dsg.executeRead(() -> {
                    Set<Quad> expected = Set.of(
                            Quad.create(Quad.defaultGraphIRI, uri("s1"), uri("p"), uri("o1")),
                            Quad.create(Quad.defaultGraphIRI, uri("s2"), uri("p"), uri("o2")),
                            Quad.create(uri("g"), uri("s3"), uri("p"), uri("o3")));
                    assertEquals(expected, Iter.toSet(dsg.find()));
                    for ( Quad q : expected ) {
                        for ( int mask = 0; mask < 16; mask++ ) {
                            Node g = (mask & 1) == 0 ? Node.ANY : q.getGraph();
                            Node s = (mask & 2) == 0 ? Node.ANY : q.getSubject();
                            Node p = (mask & 4) == 0 ? Node.ANY : q.getPredicate();
                            Node o = (mask & 8) == 0 ? Node.ANY : q.getObject();
                            Set<Quad> matches = expected.stream().filter(x ->
                                    (g == Node.ANY || g.equals(x.getGraph())) &&
                                    (s == Node.ANY || s.equals(x.getSubject())) &&
                                    (p == Node.ANY || p.equals(x.getPredicate())) &&
                                    (o == Node.ANY || o.equals(x.getObject())))
                                    .collect(java.util.stream.Collectors.toSet());
                            assertEquals(matches, Iter.toSet(dsg.find(g, s, p, o)));
                        }
                    }
                });
            }
        });
    }

    private static Node uri(String local) { return NodeFactory.createURI("urn:" + local); }

    @Test
    public void customSortProgram() throws Exception {
        List<String> invocations = loadWithSortWrapper(null);
        assertEquals(4, invocations.size(), "Node table and three index sorts");
        assertTrue(invocations.get(0).endsWith("--key=1,1"), invocations.get(0));
        assertFalse(invocations.get(0).contains("--compress-program"), invocations.get(0));
        // Index sorts compress their temporary files with gzip by default.
        assertTrue(invocations.get(2).endsWith("--compress-program=" + BulkLoaderX.gzipProgram()
                + " --key=2,2 --key=3,3 --key=1,1"), invocations.get(2));
    }

    @Test
    public void customSortCompressProgram() throws Exception {
        // Tiny inputs do not spill, so sort never runs the compressor; check its argument.
        String compress = directory.resolve("fast-zip").toString();
        List<String> invocations = loadWithSortWrapper(compress);
        assertEquals(4, invocations.size(), "Node table and three index sorts");
        assertFalse(invocations.get(0).contains("--compress-program"), invocations.get(0));
        for ( String indexSort : invocations.subList(1, 4) )
            assertTrue(indexSort.contains(" --compress-program=" + compress + " "), indexSort);
    }

    @Test
    public void compressedNodeTableSort() throws Exception {
        String compress = directory.resolve("fast-zip").toString();
        boolean saved = BulkLoaderX.CompressSortNodeTableFiles;
        BulkLoaderX.CompressSortNodeTableFiles = true;
        List<String> invocations;
        try {
            invocations = loadWithSortWrapper(compress);
        } finally {
            BulkLoaderX.CompressSortNodeTableFiles = saved;
        }
        assertEquals(4, invocations.size(), "Node table and three index sorts");
        assertTrue(invocations.get(0).contains(" --key=1,1 "), invocations.get(0));
        assertTrue(invocations.get(0).endsWith(" --compress-program=" + compress), invocations.get(0));
    }

    /** Load two triples through a sort wrapper; return the recorded sort arguments. */
    private List<String> loadWithSortWrapper(String sortCompressProgram) throws Exception {
        return loadWithSortWrapper(sortCompressProgram, false);
    }

    private List<String> loadWithSortWrapper(String sortCompressProgram, boolean parallelIndexes) throws Exception {
        requireSort();
        assumeTrue(Files.isExecutable(Path.of("/bin/sh")), "/bin/sh required for the sort wrapper");
        return assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            XLoaderFiles files = files();
            // Records each invocation, then delegates to GNU sort.
            Path calls = directory.resolve("calls.txt");
            Path wrapper = directory.resolve("wrapped-sort");
            Files.writeString(wrapper, "#!/bin/sh\necho \"$@\" >> '" + calls + "'\nexec sort \"$@\"\n");
            assertTrue(wrapper.toFile().setExecutable(true));
            Path input = rdf("<urn:s1> <urn:p> <urn:o1> .\n<urn:s2> <urn:p> <urn:o2> .\n", "nt");
            List<String> inputs = List.of(input.toString());
            ProcBuildNodeTableX.exec(database(), files, wrapper.toString(), sortCompressProgram, 2, null, inputs);
            ProcIngestDataX.exec(database(), files, inputs, false);
            if ( parallelIndexes ) {
                ProcBuildIndexX.exec(database(), List.of("SPO", "POS", "OSP"), wrapper.toString(), sortCompressProgram, 2, null, files);
            } else {
                for ( String index : List.of("SPO", "POS", "OSP") )
                    ProcBuildIndexX.exec(database(), index, wrapper.toString(), sortCompressProgram, 2, null, files);
            }

            var dsg = DatabaseMgr.connectDatasetGraph(database());
            try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
                dsg.executeRead(() -> assertEquals(Set.of(
                        Quad.create(Quad.defaultGraphIRI, uri("s1"), uri("p"), uri("o1")),
                        Quad.create(Quad.defaultGraphIRI, uri("s2"), uri("p"), uri("o2"))),
                        Iter.toSet(dsg.find())));
            }
            return Files.readAllLines(calls);
        });
    }

    @Test
    public void parallelIndexes() throws Exception {
        // Same data as built one index at a time (checked by loadWithSortWrapper).
        List<String> invocations = loadWithSortWrapper(null, true);
        assertEquals(4, invocations.size(), "Node table and three index sorts");
        assertTrue(invocations.get(0).contains(" --buffer-size=50% "), invocations.get(0));
        // The default 50% is shared between the three index sorts.
        for ( String indexSort : invocations.subList(1, 4) )
            assertTrue(indexSort.contains(" --buffer-size=16% "), indexSort);
        for ( String keys : List.of("--key=1,1 --key=2,2 --key=3,3", "--key=2,2 --key=3,3 --key=1,1", "--key=3,3 --key=1,1 --key=2,2") )
            assertTrue(invocations.stream().anyMatch(x -> x.endsWith(keys)), keys);
    }

    @Test
    public void sortBufferSizeApplies() throws Exception {
        String saved = BulkLoaderX.SortBufferSize;
        BulkLoaderX.SortBufferSize = "1024M";
        List<String> invocations;
        try {
            invocations = loadWithSortWrapper(null, true);
        } finally {
            BulkLoaderX.SortBufferSize = saved;
        }
        // A fixed size is per sort, not shared.
        for ( String sort : invocations )
            assertTrue(sort.contains(" --buffer-size=1024M "), sort);
    }

    @Test
    public void sortBufferSizeRules() {
        assertEquals("50%", BulkLoaderX.sortBufferSize("50%", 1));
        assertEquals("16%", BulkLoaderX.sortBufferSize("50%", 3));
        assertEquals("8%", BulkLoaderX.sortBufferSize("50%", 6));
        assertEquals("1%", BulkLoaderX.sortBufferSize("2%", 3));
        assertEquals("1024M", BulkLoaderX.sortBufferSize("1024M", 3));
        for ( String ok : List.of("50%", "4G", "1024M", "512k", "100000", "2T") )
            assertTrue(BulkLoaderX.isSortBufferSize(ok), ok);
        for ( String bad : List.of("", "0", "50%%", "-1G", "4GB", "1.5G", "half") )
            assertFalse(BulkLoaderX.isSortBufferSize(bad), bad);
    }

    @Test
    public void parallelIndexFailureStopsOtherSorts() throws Exception {
        requireSort();
        assumeTrue(Files.isExecutable(Path.of("/bin/sh")), "/bin/sh required for the sort wrapper");
        XLoaderFiles files = files();
        Path input = rdf("<urn:s1> <urn:p> <urn:o1> .\n<urn:s2> <urn:p> <urn:o2> .\n", "nt");
        List<String> inputs = List.of(input.toString());
        ProcBuildNodeTableX.exec(database(), files, 2, null, inputs);
        ProcIngestDataX.exec(database(), files, inputs, false);
        // POS fails at once; SPO and OSP would hang without cancellation.
        Path started = directory.resolve("started.txt");
        Path wrapper = directory.resolve("failing-pos-sort");
        Files.writeString(wrapper, "#!/bin/sh\n"
                + "case \"$*\" in\n"
                + "  *'--key=2,2 --key=3,3 --key=1,1') sleep 1; echo 'POS failed' 1>&2; exit 3 ;;\n"
                + "esac\n"
                + "echo $$ >> '" + started + "'\n"
                + "sleep 60\n"
                + "exec sort \"$@\"\n");
        assertTrue(wrapper.toFile().setExecutable(true));
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            TDBException ex = assertThrows(TDBException.class, () ->
                ProcBuildIndexX.exec(database(), List.of("SPO", "POS", "OSP"), wrapper.toString(), null, 2, null, files));
            assertTrue(ex.getMessage().contains("Sort RC = 3"), ex.getMessage());
        });
        // The other two sorts were stopped, not left running.
        for ( String pid : Files.readAllLines(started) )
            assertFalse(ProcessHandle.of(Long.parseLong(pid.trim())).map(ProcessHandle::isAlive).orElse(false), "sort " + pid + " stopped");
        assertCanReopen();
    }

    private Path gzipRdf(String contents) throws IOException {
        Path input = directory.resolve("input.nt.gz");
        try ( OutputStream out = new GZIPOutputStream(Files.newOutputStream(input)) ) {
            out.write(contents.getBytes(StandardCharsets.UTF_8));
        }
        return input;
    }

    @Test
    public void parallelParseLoad() throws Exception {
        requireSort();
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            XLoaderFiles files = files();
            StringBuilder sb = new StringBuilder();
            for ( int i = 0 ; i < 2_000 ; i++ ) {
                sb.append("<urn:s").append(i / 4).append("> <urn:p").append(i % 3).append("> \"v").append(i).append("\"@en .\n");
                sb.append("_:b").append(i % 17).append(" <urn:q> <urn:o").append(i % 50).append("> .\n");
            }
            Path input = gzipRdf(sb.toString());
            List<String> inputs = List.of(input.toString());
            int savedThreads = BulkLoaderX.ParseThreads;
            int savedChunk = BulkLoaderX.ParseChunkSize;
            BulkLoaderX.ParseThreads = 4;
            BulkLoaderX.ParseChunkSize = 256;
            try {
                ProcBuildNodeTableX.exec(database(), files, 2, null, inputs);
            } finally {
                BulkLoaderX.ParseThreads = savedThreads;
                BulkLoaderX.ParseChunkSize = savedChunk;
            }
            ProcIngestDataX.exec(database(), files, inputs, false);
            for ( String index : List.of("SPO", "POS", "OSP") )
                ProcBuildIndexX.exec(database(), index, 2, null, files);
            Graph expected = org.apache.jena.sparql.graph.GraphFactory.createDefaultGraph();
            // By file name, which handles .gz (as xloader opens it).
            org.apache.jena.riot.RDFParser.source(input.toString()).parse(expected);
            var dsg = DatabaseMgr.connectDatasetGraph(database());
            try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
                dsg.executeRead(() -> {
                    assertEquals(expected.size(), dsg.getDefaultGraph().size());
                    assertTrue(expected.isIsomorphicWith(dsg.getDefaultGraph()), "Same graph, up to blank node labels");
                });
            }
        });
    }

    /** Blank nodes in the node table, and distinct blank nodes used in the default graph. */
    private long[] blankNodeCounts() {
        var dsg = DatabaseMgr.connectDatasetGraph(database());
        try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
            return dsg.calculateRead(() -> {
                var nt = TDBInternal.getDatasetGraphTDB(dsg).getTripleTable().getNodeTupleTable().getNodeTable();
                long inTable = Iter.count(Iter.filter(nt.all(), p -> p.getRight().isBlank()));
                Set<Node> used = new java.util.HashSet<>();
                dsg.find().forEachRemaining(q -> {
                    if ( q.getSubject().isBlank() ) used.add(q.getSubject());
                    if ( q.getObject().isBlank() ) used.add(q.getObject());
                });
                return new long[] {inTable, used.size()};
            });
        }
    }

    private List<String> blankNodeFiles() throws IOException {
        // The same labels in two files: different blank nodes (one document each).
        Path a = directory.resolve("a.nt");
        Path b = directory.resolve("b.nt");
        StringBuilder sa = new StringBuilder();
        StringBuilder sb = new StringBuilder();
        for ( int i = 0 ; i < 300 ; i++ ) {
            sa.append("_:x").append(i % 10).append(" <urn:p> \"a").append(i).append("\" .\n");
            sb.append("<urn:s").append(i).append("> <urn:q> _:x").append(i % 10).append(" .\n");
        }
        Files.writeString(a, sa.toString());
        Files.writeString(b, sb.toString());
        return List.of(a.toString(), b.toString());
    }

    private void loadBlankNodes(int parseThreads) throws Exception {
        requireSort();
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            XLoaderFiles files = files();
            List<String> inputs = blankNodeFiles();
            int savedThreads = BulkLoaderX.ParseThreads;
            int savedChunk = BulkLoaderX.ParseChunkSize;
            BulkLoaderX.ParseThreads = parseThreads;
            BulkLoaderX.ParseChunkSize = 200;
            try {
                ProcBuildNodeTableX.exec(database(), files, 2, null, inputs);
            } finally {
                BulkLoaderX.ParseThreads = savedThreads;
                BulkLoaderX.ParseChunkSize = savedChunk;
            }
            assertTrue(Files.isRegularFile(Path.of(files.blankNodeSeed)), "Seed written by the node table step");
            ProcIngestDataX.exec(database(), files, inputs, false);
            for ( String index : List.of("SPO", "POS", "OSP") )
                ProcBuildIndexX.exec(database(), index, 2, null, files);
            long[] counts = blankNodeCounts();
            assertEquals(20, counts[1], "Ten labels in each of two files");
            assertEquals(counts[1], counts[0], "No unused blank nodes in the node table");
        });
    }

    @Test
    public void blankNodesFoundByIngest() throws Exception {
        loadBlankNodes(1);
    }

    @Test
    public void blankNodesFoundByIngestParallelParse() throws Exception {
        loadBlankNodes(4);
    }

    @Test
    public void ingestWithoutSeedFile() throws Exception {
        requireSort();
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            XLoaderFiles files = files();
            List<String> inputs = blankNodeFiles();
            ProcBuildNodeTableX.exec(database(), files, 2, null, inputs);
            // As before the seed: ingest labels blank nodes itself and allocates them.
            Files.delete(Path.of(files.blankNodeSeed));
            ProcIngestDataX.exec(database(), files, inputs, false);
            for ( String index : List.of("SPO", "POS", "OSP") )
                ProcBuildIndexX.exec(database(), index, 2, null, files);
            long[] counts = blankNodeCounts();
            assertEquals(20, counts[1]);
            assertEquals(40, counts[0], "The node table step's blank nodes are unused");
        });
    }

    /** Run node table, ingest and index steps with the given parse threads (small chunks). */
    private void loadParallel(XLoaderFiles files, List<String> inputs, int parseThreads, boolean deleteSeed, List<String> indexes) {
        int savedThreads = BulkLoaderX.ParseThreads;
        int savedChunk = BulkLoaderX.ParseChunkSize;
        BulkLoaderX.ParseThreads = parseThreads;
        BulkLoaderX.ParseChunkSize = 256;
        try {
            ProcBuildNodeTableX.exec(database(), files, 2, null, inputs);
            if ( deleteSeed ) {
                try { Files.delete(Path.of(files.blankNodeSeed)); }
                catch (IOException ex) { throw new RuntimeException(ex); }
            }
            ProcIngestDataX.exec(database(), files, inputs, false);
        } finally {
            BulkLoaderX.ParseThreads = savedThreads;
            BulkLoaderX.ParseChunkSize = savedChunk;
        }
        for ( String index : indexes )
            ProcBuildIndexX.exec(database(), index, 2, null, files);
    }

    private String loadInfo(XLoaderFiles files) throws IOException {
        return Files.readString(Path.of(files.loadInfo)).replaceAll("\\s", "");
    }

    @Test
    public void parallelIngestTriples() throws Exception {
        requireSort();
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            List<String> inputs = blankNodeFiles();
            XLoaderFiles files = files();
            for ( boolean deleteSeed : new boolean[] {false, true} ) {
                // Without the seed file, the node table step's blank nodes are not found:
                // ingest workers send them to the writer thread to allocate.
                FileOps.clearAll(files.TMPDIR);
                loadParallel(files, inputs, 4, deleteSeed, List.of("SPO", "POS", "OSP"));
                assertTrue(loadInfo(files).contains("\"triples\":600"), loadInfo(files));
                Graph expected = org.apache.jena.sparql.graph.GraphFactory.createDefaultGraph();
                for ( String f : inputs )
                    org.apache.jena.riot.RDFParser.source(f).parse(expected);
                var dsg = DatabaseMgr.connectDatasetGraph(database());
                try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
                    dsg.executeRead(() -> {
                        assertEquals(600, dsg.getDefaultGraph().size());
                        assertTrue(expected.isIsomorphicWith(dsg.getDefaultGraph()), "Same graph, up to blank nodes");
                    });
                }
                long[] counts = blankNodeCounts();
                assertEquals(20, counts[1]);
                assertEquals(deleteSeed ? 40 : 20, counts[0], "Unused node table entries only without the seed");
                FileOps.clearAll(database());
            }
        });
    }

    @Test
    public void ingestCacheSizeProperty() {
        assertEquals(10_000_000, ParallelIngest.cacheSize(null));
        assertEquals(10_000_000, ParallelIngest.cacheSize(" "));
        assertEquals(5_000_000, ParallelIngest.cacheSize("5000000"));
        assertEquals(5_000_000, ParallelIngest.cacheSize("5_000_000"));
        assertThrows(TDBException.class, () -> ParallelIngest.cacheSize("5M"));
        assertThrows(TDBException.class, () -> ParallelIngest.cacheSize("10"));
    }

    @Test
    public void parallelIngestSmallCache() throws Exception {
        // A cache far smaller than the number of nodes: most lookups go to the node table.
        int size = ParallelIngest.CacheSize;
        try {
            ParallelIngest.CacheSize = 10;
            parallelIngestTriples();
        } finally {
            ParallelIngest.CacheSize = size;
        }
    }

    @Test
    public void parallelIngestNodeTableInMemory() throws Exception {
        // The node table's mapping in memory, with a tiny cache so most lookups reach it;
        // with and without the seed file (blank nodes always use the B+tree).
        int size = ParallelIngest.CacheSize;
        try {
            BulkLoaderX.NodeTableInMemory = true;
            ParallelIngest.CacheSize = 10;
            parallelIngestTriples();
        } finally {
            BulkLoaderX.NodeTableInMemory = false;
            ParallelIngest.CacheSize = size;
        }
    }

    @Test
    public void compactNodeTableFromXLoaderNodeTable() throws Exception {
        // A node table built by the node table step: NodeIds increase with the hashes, so
        // the table builds and gives every record's NodeId.
        requireSort();
        XLoaderFiles files = files();
        loadParallel(files, blankNodeFiles(), 4, false, List.of("SPO"));
        var dsg = DatabaseMgr.connectDatasetGraph(database());
        try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
            dsg.executeRead(() -> {
                var nodeTable = (org.apache.jena.tdb2.store.nodetable.NodeTableTRDF)TDBInternal.getDatasetGraphTDB(dsg)
                        .getTripleTable().getNodeTupleTable().getNodeTable().baseNodeTable();
                var index = nodeTable.getIndex();
                long n = index.size();
                assertTrue(n > 0);
                CompactNodeTable table;
                try {
                    table = CompactNodeTable.build(index.iterator(), n, nodeTable.getData().length());
                } catch (CompactNodeTable.NotApplicable ex) {
                    throw new AssertionError(ex.getMessage());
                }
                assertEquals(n, table.size());
                index.iterator().forEachRemaining(r -> assertEquals(org.apache.jena.atlas.lib.Bytes.getLong(r.getValue(), 0),
                                                                    table.find(org.apache.jena.atlas.lib.Bytes.getLong(r.getKey(), 0))));
            });
        }
    }

    @Test
    public void ingestThreadsOverride() throws Exception {
        requireSort();
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            // One parse thread for the node table step, many for ingest only.
            List<String> inputs = blankNodeFiles();
            XLoaderFiles files = files();
            int saved = BulkLoaderX.IngestThreads;
            int savedChunk = BulkLoaderX.ParseChunkSize;
            BulkLoaderX.IngestThreads = 16;
            BulkLoaderX.ParseChunkSize = 256;
            try {
                ProcBuildNodeTableX.exec(database(), files, 2, null, inputs);
                ProcIngestDataX.exec(database(), files, inputs, false);
            } finally {
                BulkLoaderX.IngestThreads = saved;
                BulkLoaderX.ParseChunkSize = savedChunk;
            }
            for ( String index : List.of("SPO", "POS", "OSP") )
                ProcBuildIndexX.exec(database(), index, 2, null, files);
            Graph expected = org.apache.jena.sparql.graph.GraphFactory.createDefaultGraph();
            for ( String f : inputs )
                org.apache.jena.riot.RDFParser.source(f).parse(expected);
            var dsg = DatabaseMgr.connectDatasetGraph(database());
            try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
                dsg.executeRead(() -> assertTrue(expected.isIsomorphicWith(dsg.getDefaultGraph())));
            }
            long[] counts = blankNodeCounts();
            assertEquals(20, counts[1]);
            assertEquals(20, counts[0], "Ingest with its own thread count finds the node table step's blank nodes");
        });
    }

    @Test
    public void preloadNodeTable() throws Exception {
        requireSort();
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            XLoaderFiles files = files();
            Path input = rdf("<urn:s1> <urn:p> <urn:o1> .\n<urn:s2> <urn:p> \"x\" .\n", "nt");
            List<String> inputs = List.of(input.toString());
            ProcBuildNodeTableX.exec(database(), files, 2, null, inputs);
            boolean saved = BulkLoaderX.PreloadNodeTable;
            BulkLoaderX.PreloadNodeTable = true;
            try {
                ProcIngestDataX.exec(database(), files, inputs, false);
            } finally {
                BulkLoaderX.PreloadNodeTable = saved;
            }
            for ( String index : List.of("SPO", "POS", "OSP") )
                ProcBuildIndexX.exec(database(), index, 2, null, files);
            var dsg = DatabaseMgr.connectDatasetGraph(database());
            try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
                dsg.executeRead(() -> assertEquals(2, Iter.count(dsg.find())));
            }
        });
    }

    @Test
    public void parallelIngestQuads() throws Exception {
        requireSort();
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            StringBuilder sb = new StringBuilder();
            for ( int i = 0 ; i < 1_000 ; i++ ) {
                sb.append("<urn:s").append(i % 37).append("> <urn:p> \"v").append(i).append("\"");
                // Named graphs, and some quads in the default graph (written as triples).
                if ( i % 4 != 0 )
                    sb.append(" <urn:g").append(i % 3).append(">");
                sb.append(" .\n");
            }
            Path input = rdf(sb.toString(), "nq");
            XLoaderFiles files = files();
            loadParallel(files, List.of(input.toString()), 4, false,
                         List.of("SPO", "POS", "OSP", "GSPO", "GPOS", "GOSP", "SPOG", "POSG", "OSPG"));
            assertTrue(loadInfo(files).contains("\"quads\":1000"), loadInfo(files));
            DatasetGraph expected = org.apache.jena.sparql.core.DatasetGraphFactory.create();
            org.apache.jena.riot.RDFParser.source(input.toString()).parse(expected);
            var dsg = DatabaseMgr.connectDatasetGraph(database());
            try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
                dsg.executeRead(() -> {
                    Set<Quad> actual = new java.util.HashSet<>();
                    dsg.find().forEachRemaining(q -> actual.add(
                            q.isDefaultGraph() ? Quad.create(Quad.defaultGraphIRI, q.asTriple()) : q));
                    Set<Quad> want = new java.util.HashSet<>();
                    expected.find().forEachRemaining(q -> want.add(
                            q.isDefaultGraph() ? Quad.create(Quad.defaultGraphIRI, q.asTriple()) : q));
                    assertEquals(want, actual);
                });
            }
        });
    }

    @Test
    public void parallelIngestParseError() throws Exception {
        requireSort();
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            StringBuilder sb = new StringBuilder();
            for ( int i = 1 ; i <= 500 ; i++ )
                sb.append(i == 321 ? "<urn:s> <urn:p> not RDF\n" : "<urn:s" + i + "> <urn:p> <urn:o> .\n");
            Path input = rdf(sb.toString(), "nt");
            XLoaderFiles files = files();
            int savedThreads = BulkLoaderX.ParseThreads;
            int savedChunk = BulkLoaderX.ParseChunkSize;
            try {
                // The node table step on one thread fails too: build it from valid data.
                Path valid = directory.resolve("valid.nt");
                Files.writeString(valid, "<urn:s1> <urn:p> <urn:o> .\n");
                ProcBuildNodeTableX.exec(database(), files, 2, null, List.of(valid.toString()));
                BulkLoaderX.ParseThreads = 4;
                BulkLoaderX.ParseChunkSize = 256;
                org.apache.jena.riot.RiotParseException ex = assertThrows(org.apache.jena.riot.RiotParseException.class, () ->
                    ProcIngestDataX.exec(database(), files, List.of(input.toString()), false));
                assertEquals(321, ex.getLine(), ex.getMessage());
            } finally {
                BulkLoaderX.ParseThreads = savedThreads;
                BulkLoaderX.ParseChunkSize = savedChunk;
            }
            assertCanReopen();
        });
    }

    @Test
    public void missingSortProgramFails() throws Exception {
        assertTimeoutPreemptively(Duration.ofSeconds(15), () -> {
            XLoaderFiles files = files();
            String missing = directory.resolve("no-such-sort").toString();
            Path input = rdf("<urn:s> <urn:p> <urn:o> .\n", "nt");
            TDBException ex = assertThrows(TDBException.class, () ->
                ProcBuildNodeTableX.exec(database(), files, missing, null, 2, null, List.of(input.toString())));
            assertTrue(ex.getMessage().contains(missing), ex.getMessage());
            assertCanReopen();
        });
    }

    @Test
    public void sortFailureStopsNodeParser() throws Exception {
        assumeTrue(Files.isExecutable(Path.of("/bin/sh")), "/bin/sh required for the sort wrapper");
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            XLoaderFiles files = files();
            // Reads part of the node output, then fails while the parser is still running.
            Path failing = directory.resolve("failing-sort");
            Files.writeString(failing, "#!/bin/sh\ndd bs=1024 count=100 of=/dev/null 2>/dev/null\nexit 3\n");
            assertTrue(failing.toFile().setExecutable(true));
            StringBuilder data = new StringBuilder();
            for ( int i = 0; i < 200_000; i++ )
                data.append("<urn:s").append(i).append("> <urn:p> \"").append(i).append("\" .\n");
            Path input = rdf(data.toString(), "nt");
            assertThrows(RuntimeException.class, () ->
                ProcBuildNodeTableX.exec(database(), files, failing.toString(), null, 2, null, List.of(input.toString())));
            // AsyncParser stops its thread but does not wait for it when the caller
            // has been interrupted, so the thread may end just after the stage.
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while ( asyncParserRunning() && System.nanoTime() < deadline )
                Thread.sleep(10);
            assertFalse(asyncParserRunning(), "Parser thread stopped");
            assertCanReopen();
        });
    }

    private static boolean asyncParserRunning() {
        return Thread.getAllStackTraces().keySet().stream()
                .anyMatch(t -> t.getName().equals("AsyncParser") && t.isAlive());
    }

    @Test
    public void programAvailable() throws IOException {
        assumeTrue(Files.isExecutable(Path.of("/bin/sh")), "/bin/sh required");
        assertTrue(BulkLoaderX.programAvailable("/bin/sh"));
        assertTrue(BulkLoaderX.programAvailable("sh"), "Found on the PATH");
        assertFalse(BulkLoaderX.programAvailable(directory.resolve("no-such-program").toString()));
        assertFalse(BulkLoaderX.programAvailable("no-such-program-for-xloader"));
        Path plain = Files.writeString(directory.resolve("not-executable"), "");
        assertFalse(BulkLoaderX.programAvailable(plain.toString()));
        assertFalse(BulkLoaderX.programAvailable(directory.toString()), "A directory is not a program");
    }

    @Test
    public void malformedNodeInputPropagates() throws Exception {
        requireSort();
        assertTimeoutPreemptively(Duration.ofSeconds(15), () -> {
            XLoaderFiles files = files();
            Path input = rdf("<urn:s> <urn:p> <urn:o> .\nnot RDF\n", "nt");
            assertThrows(RiotException.class, () ->
                ProcBuildNodeTableX.exec(database(), files, 2, null, List.of(input.toString())));
            assertCanReopen();
        });
    }

    @Test
    public void malformedIngestClosesBothOutputs() throws Exception {
        XLoaderFiles files = files();
        Path input = rdf("<urn:s> <urn:p> <urn:o> .\nnot RDF\n", "nt");
        assertThrows(RiotException.class, () ->
            ProcIngestDataX.exec(database(), files, List.of(input.toString()), false));
        // Closing gzip outputs writes their trailers even after a parser error.
        assertValidGzip(files.triplesFile);
        assertValidGzip(files.quadsFile);
        assertFalse(Files.exists(Path.of(files.loadInfo)));
        assertCanReopen();
    }

    @Test
    public void workfileGzipLevel() throws Exception {
        StringBuilder rdf = new StringBuilder();
        for ( int i = 0; i < 200; i++ )
            rdf.append("<urn:s").append(i).append("> <urn:p> <urn:o").append(i).append("> .\n");
        Path input = rdf(rdf.toString(), "nt");
        long stored = ingestTriplesSize(input, "stored", Deflater.NO_COMPRESSION);
        long fast = ingestTriplesSize(input, "fast", BulkLoaderX.WorkfileGzipLevel);
        assertTrue(stored > fast, "Level 0 workfile ("+stored+") should be larger than level 1 ("+fast+")");
    }

    private long ingestTriplesSize(Path input, String name, int gzipLevel) throws IOException {
        XLoaderFiles files = new XLoaderFiles(Files.createDirectory(directory.resolve("tmp-" + name)).toString());
        ProcIngestDataX.exec(directory.resolve("db-" + name).toString(), files, List.of(input.toString()), false,
                             gzipLevel, 4096);
        assertValidGzip(files.triplesFile);
        assertValidGzip(files.quadsFile);
        return Files.size(Path.of(files.triplesFile));
    }

    @Test
    public void secondOutputOpenFailureClosesFirst() throws Exception {
        XLoaderFiles files = files();
        Files.createDirectory(Path.of(files.quadsFile));
        Path input = rdf("", "nt");
        assertThrows(RuntimeException.class, () ->
            ProcIngestDataX.exec(database(), files, List.of(input.toString()), false));
        assertValidGzip(files.triplesFile);
        assertCanReopen();
    }

    @Test
    public void malformedIndexInputAbortsBuild() throws Exception {
        requireSort();
        assertTimeoutPreemptively(Duration.ofSeconds(15), () -> {
            XLoaderFiles files = files();
            try ( OutputStream output = new GZIPOutputStream(Files.newOutputStream(Path.of(files.triplesFile))) ) {
                output.write("short record\n".getBytes(StandardCharsets.UTF_8));
            }
            assertThrows(RuntimeException.class, () ->
                ProcBuildIndexX.exec(database(), "SPO", 2, null, files));
            assertCanReopen();
        });
    }

    @Test
    public void nodeOutputFailurePropagates() {
        OutputStream broken = new OutputStream() {
            @Override public void write(int value) throws IOException {
                throw new IOException("simulated write failure");
            }
        };
        var stream = new ProcBuildNodeTableX.NodeHashTmpStream(broken);
        TDBException ex = assertThrows(TDBException.class, () ->
            stream.triple(Triple.create(uri("s"), uri("p"), uri("o"))));
        assertInstanceOf(IOException.class, ex.getCause());
    }

    private void assertCanReopen() {
        var dsg = DatabaseMgr.connectDatasetGraph(database());
        try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
            dsg.executeWrite(() -> dsg.add(Quad.create(Quad.defaultGraphNodeGenerated, uri("check"), uri("p"), uri("o"))));
        }
    }

    private void assertValidGzip(String file) throws IOException {
        try ( InputStream input = new GZIPInputStream(Files.newInputStream(Path.of(file))) ) {
            input.transferTo(OutputStream.nullOutputStream());
        }
    }
}
