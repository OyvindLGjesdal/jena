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
import java.util.ArrayList;
import java.util.List;

import org.apache.jena.atlas.lib.Bytes;
import org.apache.jena.dboe.base.file.BinaryDataFile;
import org.apache.jena.dboe.base.file.BinaryDataFileMem;
import org.apache.jena.dboe.base.record.Record;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.riot.thrift.ThriftConvert;
import org.junit.jupiter.api.Test;

public class TestSortedNodeRecords {

    /** Sorted node lines as the node table step writes them: hash and Thrift term in hex. */
    private static String lines(List<Node> nodes) throws Exception {
        var out = new ByteArrayOutputStream();
        var stream = new ProcBuildNodeTableX.NodeHashTmpStream(out);
        for ( Node n : nodes )
            stream.triple(org.apache.jena.graph.Triple.create(n, NodeFactory.createURI("urn:p"), NodeFactory.createURI("urn:o")));
        stream.finish();
        return out.toString(StandardCharsets.US_ASCII);
    }

    private static List<Record> read(String text, BinaryDataFile objectFile) {
        return read(text, objectFile, 1);
    }

    private static List<Record> read(String text, BinaryDataFile objectFile, int decoders) {
        List<Record> records = new ArrayList<>();
        try ( SortedNodeRecords it = new SortedNodeRecords(new ByteArrayInputStream(text.getBytes(StandardCharsets.US_ASCII)), objectFile, decoders) ) {
            it.forEachRemaining(records::add);
        }
        return records;
    }

    private static BinaryDataFile mem() {
        BinaryDataFile f = new BinaryDataFileMem();
        f.open();
        return f;
    }

    @Test
    public void recordsAndObjectFile() throws Exception {
        recordsAndObjectFile(1);
    }

    @Test
    public void recordsAndObjectFileFourDecoders() throws Exception {
        // About 3 MB of lines: several blocks decoded out of order, written in order.
        recordsAndObjectFile(4);
    }

    private void recordsAndObjectFile(int decoders) throws Exception {
        List<Node> nodes = new ArrayList<>();
        for ( int i = 0 ; i < 25_000 ; i++ )
            nodes.add(NodeFactory.createURI("urn:s" + i + "/" + "x".repeat(40)));
        String text = lines(nodes);
        BinaryDataFile objectFile = mem();
        List<Record> records = read(text, objectFile, decoders);
        // urn:p and urn:o as well, written once each.
        assertEquals(25_002, records.size());
        String[] l = text.split("\n");
        long offset = 0;
        for ( int i = 0 ; i < records.size() ; i++ ) {
            Record r = records.get(i);
            String[] parts = l[i].split(" ");
            assertEquals(parts[0], Bytes.asHexUC(r.getKey()));
            // The NodeId is the term's offset in the object file.
            assertEquals(offset, Bytes.getLong(r.getValue()));
            byte[] term = new byte[parts[1].length() / 2];
            objectFile.read(offset, term);
            assertEquals(parts[1], Bytes.asHexUC(term));
            offset += term.length;
        }
        assertEquals(offset, objectFile.length());
    }

    @Test
    public void lastLineWithoutNewline() throws Exception {
        String text = lines(List.of(NodeFactory.createURI("urn:a")));
        assertEquals(3, read(text.substring(0, text.length() - 1), mem()).size());
    }

    @Test
    public void emptyInput() {
        assertEquals(0, read("", mem()).size());
    }

    private static Exception failure(String text) {
        Exception one = assertThrows(RuntimeException.class, () -> read(text, mem(), 1));
        Exception four = assertThrows(RuntimeException.class, () -> read(text, mem(), 4));
        assertEquals(one.getClass(), four.getClass());
        assertEquals(one.getMessage(), four.getMessage());
        return one;
    }

    @Test
    public void badInput() throws Exception {
        String good = lines(List.of(NodeFactory.createURI("urn:a")));
        String first = good.substring(0, good.indexOf('\n') + 1);
        assertTrue(failure(first + "\n" + first).getMessage().contains("empty line"));
        assertTrue(failure("0123\n").getMessage().contains("incomplete node hash"));
        assertTrue(failure(first.replace(' ', 'A')).getMessage().contains("missing separator"));
        // A bad hex character, with the usual message (the uutils empty line case gave 0x0A).
        assertTrue(failure("Z" + first.substring(1)).getMessage().contains("Bad hex char"));
        // Valid hex that is not a Thrift term.
        String hash = first.substring(0, first.indexOf(' '));
        failure(hash + " FFFFFFFF\n");
    }

    @Test
    public void closeStopsReader() throws Exception {
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            List<Node> nodes = new ArrayList<>();
            for ( int i = 0 ; i < 200_000 ; i++ )
                nodes.add(NodeFactory.createURI("urn:s" + i));
            String text = lines(nodes);
            try ( SortedNodeRecords it = new SortedNodeRecords(new ByteArrayInputStream(text.getBytes(StandardCharsets.US_ASCII)), mem(), 4) ) {
                assertTrue(it.hasNext());
                it.next();
            }
            // The reader thread ends soon after close, without the rest being read.
            long deadline = System.nanoTime() + 10_000_000_000L;
            while ( readerRunning() && System.nanoTime() < deadline )
                Thread.sleep(10);
            assertFalse(readerRunning());
        });
    }

    private static boolean readerRunning() {
        return Thread.getAllStackTraces().keySet().stream().anyMatch(t -> t.getName().startsWith("tdb2-xloader-terms") && t.isAlive());
    }

    @Test
    public void thriftCheckMatchesDecoder() throws Exception {
        // Sanity check of the test data: the terms in the lines decode as Thrift.
        String text = lines(List.of(NodeFactory.createLiteralLang("x", "en")));
        String hex = text.substring(text.indexOf(' ') + 1, text.indexOf('\n'));
        byte[] t = new byte[hex.length() / 2];
        for ( int i = 0 ; i < t.length ; i++ )
            t[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        ThriftConvert.termFromBytes(new org.apache.jena.riot.thrift.wire.RDF_Term(), t);
    }
}
