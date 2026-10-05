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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.apache.jena.atlas.lib.Bytes;
import org.apache.jena.dboe.base.record.Record;
import org.apache.jena.dboe.base.record.RecordFactory;
import org.junit.jupiter.api.Test;

public class TestCompactNodeTable {

    private static final RecordFactory factory = new RecordFactory(16, 8);

    // ---- EliasFano

    private static EliasFano sequence(long[] values, long capacity, int universeBits) {
        EliasFano.Builder b = new EliasFano.Builder(capacity, universeBits);
        for ( long v : values )
            b.add(v);
        return b.build();
    }

    private static long[] sortedUnsigned(long[] values) {
        Long[] boxed = Arrays.stream(values).boxed().toArray(Long[]::new);
        Arrays.sort(boxed, Long::compareUnsigned);
        return Arrays.stream(boxed).mapToLong(Long::longValue).toArray();
    }

    @Test
    public void eliasFanoRandom64() {
        Random random = new Random(1);
        for ( int n : new int[] {1, 2, 3, 100, 511, 512, 513, 10_000, 100_000} ) {
            long[] values = new long[n];
            for ( int i = 0 ; i < n ; i++ )
                values[i] = random.nextLong();
            values = sortedUnsigned(values);
            // Capacity above the count, as the table's bound from the file size.
            EliasFano ef = sequence(values, n + n / 3 + 1, 64);
            assertEquals(n, ef.size());
            for ( int i = 0 ; i < n ; i++ ) {
                assertEquals(values[i], ef.get(i), "get " + i + " of " + n);
                assertEquals(i, ef.indexOf(values[i]), "indexOf " + i + " of " + n);
            }
            for ( int i = 0 ; i < 1000 ; i++ ) {
                long x = random.nextLong();
                if ( Arrays.binarySearch(values, x) < 0 && Arrays.stream(values).noneMatch(v -> v == x) )
                    assertEquals(EliasFano.NOT_FOUND, ef.indexOf(x));
            }
        }
    }

    @Test
    public void eliasFanoDense() {
        // Small gaps and a small universe: few or no low bits.
        for ( int universeBits : new int[] {12, 16, 20, 40} ) {
            Random random = new Random(universeBits);
            List<Long> list = new ArrayList<>();
            long v = 0;
            long limit = 1L << universeBits;
            while ( list.size() < 3000 ) {
                v += 1 + random.nextInt(3);
                if ( v >= limit )
                    break;
                list.add(v);
            }
            long[] values = list.stream().mapToLong(Long::longValue).toArray();
            EliasFano ef = sequence(values, values.length, universeBits);
            for ( int i = 0 ; i < values.length ; i++ ) {
                assertEquals(values[i], ef.get(i));
                assertEquals(i, ef.indexOf(values[i]));
            }
        }
    }

    @Test
    public void eliasFanoEdges() {
        long[] values = {0, 1, 2, 0x7FFF_FFFF_FFFF_FFFFL, 0x8000_0000_0000_0000L, -2, -1};
        EliasFano ef = sequence(values, values.length, 64);
        for ( int i = 0 ; i < values.length ; i++ ) {
            assertEquals(values[i], ef.get(i));
            assertEquals(i, ef.indexOf(values[i]));
        }
        assertEquals(EliasFano.NOT_FOUND, ef.indexOf(3));
        assertEquals(EliasFano.NOT_FOUND, ef.indexOf(-3));
    }

    @Test
    public void eliasFanoDuplicates() {
        long[] values = {5, 9, 9, 12};
        EliasFano ef = sequence(values, 10, 64);
        assertEquals(EliasFano.DUPLICATE, ef.indexOf(9));
        assertEquals(0, ef.indexOf(5));
        assertEquals(3, ef.indexOf(12));
        assertEquals(9, ef.get(1));
        assertEquals(9, ef.get(2));
    }

    @Test
    public void eliasFanoOrderAndCapacity() {
        EliasFano.Builder b = new EliasFano.Builder(2, 64);
        b.add(-1);  // The largest unsigned value.
        assertThrows(IllegalArgumentException.class, () -> b.add(5));
        b.add(-1);
        assertThrows(IllegalStateException.class, () -> b.add(-1));
        EliasFano.Builder small = new EliasFano.Builder(10, 8);
        assertThrows(IllegalArgumentException.class, () -> small.add(256));
    }

    @Test
    public void longArrayChunks() {
        // Lengths at a chunk boundary are handled as in one array.
        EliasFano.LongArray a = new EliasFano.LongArray(5);
        a.set(4, 7);
        assertEquals(7, a.get(4));
        assertEquals(5, a.length());
    }

    // ---- CompactNodeTable

    private static Record record(long hashHigh, long hashLow, long nodeId) {
        byte[] key = new byte[16];
        Bytes.setLong(hashHigh, key, 0);
        Bytes.setLong(hashLow, key, 8);
        byte[] value = new byte[8];
        Bytes.setLong(nodeId, value, 0);
        return factory.create(key, value);
    }

    /** Records as the node table step writes them: hash order, NodeIds increasing. */
    private static List<Record> records(int n, long seed) {
        Random random = new Random(seed);
        long[] hashes = new long[n];
        for ( int i = 0 ; i < n ; i++ )
            hashes[i] = random.nextLong();
        hashes = sortedUnsigned(hashes);
        List<Record> records = new ArrayList<>();
        long offset = 0;
        for ( int i = 0 ; i < n ; i++ ) {
            records.add(record(hashes[i], random.nextLong(), offset));
            offset += 10 + random.nextInt(200);
        }
        return records;
    }

    private static long objectFileLength(List<Record> records) {
        return records.isEmpty() ? 0 : Bytes.getLong(records.get(records.size() - 1).getValue(), 0) + 300;
    }

    @Test
    public void tableFindsEveryRecord() throws Exception {
        List<Record> records = records(50_000, 2);
        CompactNodeTable table = CompactNodeTable.build(records.iterator(), records.size() + 100, objectFileLength(records));
        assertEquals(records.size(), table.size());
        for ( Record r : records )
            assertEquals(Bytes.getLong(r.getValue(), 0), table.find(Bytes.getLong(r.getKey(), 0)));
        Random random = new Random(3);
        for ( int i = 0 ; i < 1000 ; i++ ) {
            long h = random.nextLong();
            if ( records.stream().noneMatch(r -> Bytes.getLong(r.getKey(), 0) == h) )
                assertEquals(CompactNodeTable.NOT_FOUND, table.find(h));
        }
        // Much smaller than the B+tree's 24 bytes a record.
        assertTrue(table.bytes() < 10L * records.size(), "bytes: " + table.bytes());
    }

    @Test
    public void tableSameFirst64Bits() throws Exception {
        List<Record> records = List.of(record(10, 1, 0), record(20, 1, 50), record(20, 2, 90), record(30, 0, 120));
        CompactNodeTable table = CompactNodeTable.build(records.iterator(), 4, 200);
        assertEquals(0, table.find(10));
        assertEquals(CompactNodeTable.AMBIGUOUS, table.find(20));
        assertEquals(120, table.find(30));
        assertEquals(CompactNodeTable.NOT_FOUND, table.find(25));
    }

    @Test
    public void tableEmpty() throws Exception {
        CompactNodeTable table = CompactNodeTable.build(List.<Record>of().iterator(), 0, 0);
        assertEquals(0, table.size());
        assertEquals(CompactNodeTable.NOT_FOUND, table.find(42));
    }

    @Test
    public void tableNotApplicable() {
        // NodeIds not increasing with the hashes: not a node table built in hash order.
        List<Record> unordered = List.of(record(10, 0, 50), record(20, 0, 10));
        assertThrows(CompactNodeTable.NotApplicable.class, () -> CompactNodeTable.build(unordered.iterator(), 2, 100));
        // A NodeId outside the object file.
        List<Record> outside = List.of(record(10, 0, 50), record(20, 0, 150));
        assertThrows(CompactNodeTable.NotApplicable.class, () -> CompactNodeTable.build(outside.iterator(), 2, 100));
        // An inline NodeId (bit 63 set).
        List<Record> inline = List.of(record(10, 0, 0x8000_0000_0000_0001L));
        assertThrows(CompactNodeTable.NotApplicable.class, () -> CompactNodeTable.build(inline.iterator(), 1, 100));
        // More records than the bound.
        List<Record> more = List.of(record(10, 0, 0), record(20, 0, 10), record(30, 0, 20));
        assertThrows(CompactNodeTable.NotApplicable.class, () -> CompactNodeTable.build(more.iterator(), 2, 100));
    }
}
