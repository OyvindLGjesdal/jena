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

import java.util.Iterator;

import org.apache.jena.atlas.lib.Bytes;
import org.apache.jena.dboe.base.record.Record;

/**
 * The node table's hash to NodeId mapping in memory, for ingest's lookups.
 * <p>
 * The node table step writes the terms in hash order and a term's NodeId is its offset in
 * the object file, so in the node table's B+tree both the hashes and the NodeIds increase.
 * Two increasing sequences compress well: each is held with Elias-Fano coding
 * ({@link EliasFano}), the hashes cut to their first 64 bits. That is about 5-6 bytes a
 * term, against 24 in the B+tree's leaves, and a lookup needs no disk access.
 * <p>
 * {@link #find} answers by the first 64 bits of the hash. A node in the node table is
 * always found, with its NodeId. Two terms with the same first 64 bits give
 * {@link #AMBIGUOUS}, and the caller looks in the B+tree. A node that is not in the node
 * table is normally {@link #NOT_FOUND}, but could match another term's first 64 bits, so
 * the table is only for nodes the node table step has added: ingest uses it for the nodes
 * of the same input, not for blank nodes (whose labels depend on the parse).
 */
final class CompactNodeTable {

    static final long NOT_FOUND = -1;
    static final long AMBIGUOUS = -2;

    private final EliasFano hashes;
    private final EliasFano nodeIds;

    private CompactNodeTable(EliasFano hashes, EliasFano nodeIds) {
        this.hashes = hashes;
        this.nodeIds = nodeIds;
    }

    /** The number of terms. */
    long size() {
        return hashes.size();
    }

    /** Approximate memory use in bytes. */
    long bytes() {
        return hashes.bytes() + nodeIds.bytes();
    }

    /**
     * The NodeId value (a pointer: the offset in the object file) for the hash's first 64
     * bits (big-endian, as {@link Bytes#getLong}), or {@link #NOT_FOUND} or
     * {@link #AMBIGUOUS}.
     */
    long find(long hash64) {
        long index = hashes.indexOf(hash64);
        if ( index < 0 )
            return index == EliasFano.DUPLICATE ? AMBIGUOUS : NOT_FOUND;
        return nodeIds.get(index);
    }

    /** Why a table could not be built from the records given. */
    static final class NotApplicable extends Exception {
        NotApplicable(String message) {
            super(message, null, false, false);
        }
    }

    /**
     * Build from the node table's B+tree records (16-byte hash, 8-byte NodeId), in key order.
     *
     * @param records the records, in key order
     * @param maxRecords at least the number of records (the bound sizes the table)
     * @param objectFileLength the object file's length: every NodeId is below it
     * @throws NotApplicable if the records do not have increasing NodeIds (pointers below
     *         {@code objectFileLength}), or there are more than {@code maxRecords}
     */
    static CompactNodeTable build(Iterator<Record> records, long maxRecords, long objectFileLength)
            throws NotApplicable {
        long capacity = Math.max(1, maxRecords);
        int nodeIdBits = 64 - Long.numberOfLeadingZeros(Math.max(1, objectFileLength - 1));
        EliasFano.Builder hashes = new EliasFano.Builder(capacity, 64);
        EliasFano.Builder nodeIds = new EliasFano.Builder(capacity, nodeIdBits);
        long count = 0;
        long lastHash = 0;
        long lastNodeId = -1;
        while ( records.hasNext() ) {
            Record r = records.next();
            if ( count == capacity )
                throw new NotApplicable("more records than the bound " + capacity);
            long hash = Bytes.getLong(r.getKey(), 0);
            long nodeId = Bytes.getLong(r.getValue(), 0);
            // A pointer NodeId: bit 63 clear, an offset in the object file.
            if ( nodeId < 0 || nodeId >= objectFileLength )
                throw new NotApplicable(String.format("NodeId 0x%016X is not an offset in the object file", nodeId));
            if ( nodeId <= lastNodeId ) {
                throw new NotApplicable("NodeIds do not increase with the hashes"
                        + " (not a node table built in hash order)");
            }
            if ( count > 0 && Long.compareUnsigned(hash, lastHash) < 0 )
                throw new NotApplicable("records not in hash order");
            hashes.add(hash);
            nodeIds.add(nodeId);
            lastHash = hash;
            lastNodeId = nodeId;
            count++;
        }
        return new CompactNodeTable(hashes.build(), nodeIds.build());
    }
}
