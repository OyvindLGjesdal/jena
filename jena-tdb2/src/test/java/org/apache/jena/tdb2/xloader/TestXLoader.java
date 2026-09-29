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

    /** Load two triples through a sort wrapper; return the recorded sort arguments. */
    private List<String> loadWithSortWrapper(String sortCompressProgram) throws Exception {
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
            for ( String index : List.of("SPO", "POS", "OSP") )
                ProcBuildIndexX.exec(database(), index, wrapper.toString(), sortCompressProgram, 2, null, files);

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
