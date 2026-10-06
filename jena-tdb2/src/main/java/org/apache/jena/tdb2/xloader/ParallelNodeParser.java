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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.UUID;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.BooleanSupplier;
import java.util.function.LongConsumer;

import org.apache.jena.atlas.lib.CacheFactory;
import org.apache.jena.atlas.lib.CacheSet;
import org.apache.jena.graph.Node;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.system.StreamRDF;

/**
 * The node table step on several threads ({@link ParallelParser}): each worker writes
 * the sort lines for a chunk ({@link ProcBuildNodeTableX.NodeHashTmpStream}, with a node
 * cache shared by the workers, see {@link #SharedCache}) to a buffer, then appends the
 * whole buffer to the sort input under a lock. The order of nodes does not matter to
 * the sort.
 */
final class ParallelNodeParser {

    /**
     * One node cache shared by all workers (a concurrent Caffeine cache), so memory does
     * not grow with the number of workers, and a node one worker has written is skipped by
     * the others. Two workers may both miss a node and both write it: sort --unique
     * removes the duplicate. The system property
     * {@code jena.xloader.nodes.sharedCache=false} gives each worker its own cache of the
     * same size instead (for comparison).
     */
    static boolean SharedCache = !"false".equals(System.getProperty("jena.xloader.nodes.sharedCache"));

    private ParallelNodeParser() {}

    /**
     * Parse all of {@code input} (decompressed N-Triples or N-Quads) and write the node
     * table sort lines to {@code output}.
     * @param seed      blank node label seed for this file (see {@link BlankNodeSeed})
     * @param progress  called with the number of triples or quads in each parsed chunk
     * @return the number of triples or quads
     */
    static long parse(InputStream input, Lang lang, String baseIRI, UUID seed, OutputStream output,
                      int threads, int chunkSize, BooleanSupplier cancelled, LongConsumer progress) {
        return parse(input, lang, baseIRI, seed, output, threads, chunkSize, cancelled, progress, new LongAdder());
    }

    /** As above, adding the number of lines written for the sort to {@code lines}. */
    static long parse(InputStream input, Lang lang, String baseIRI, UUID seed, OutputStream output,
                      int threads, int chunkSize, BooleanSupplier cancelled, LongConsumer progress, LongAdder lines) {
        CacheSet<Node> shared = SharedCache ? CacheFactory.createCacheSet(ProcBuildNodeTableX.NodeHashTmpStream.CacheSize) : null;
        return ParallelParser.parse(input, lang, baseIRI, seed, threads, chunkSize, cancelled, progress,
                                    () -> new NodeWorker(output, shared != null ? shared
                                            : CacheFactory.createCacheSet(ProcBuildNodeTableX.NodeHashTmpStream.CacheSize), lines),
                                    null);
    }

    private static final class NodeWorker implements ParallelParser.Worker {
        private final OutputStream output;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream(1 << 20);
        private final ProcBuildNodeTableX.NodeHashTmpStream nodes;
        private final LongAdder lines;

        NodeWorker(OutputStream output, CacheSet<Node> cache, LongAdder lines) {
            this.output = output;
            this.nodes = new ProcBuildNodeTableX.NodeHashTmpStream(buffer, cache);
            this.lines = lines;
        }

        @Override
        public StreamRDF stream() {
            return nodes;
        }

        @Override
        public void endChunk() throws IOException {
            synchronized (output) {
                buffer.writeTo(output);
            }
            buffer.reset();
        }

        @Override
        public void close() {
            lines.add(nodes.lines());
        }
    }
}
