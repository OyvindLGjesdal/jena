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
import org.apache.jena.atlas.logging.FmtLog;
import org.apache.jena.graph.Node;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.system.StreamRDF;
import org.apache.jena.tdb2.TDBException;

/**
 * The node table step on several threads ({@link ParallelParser}): each worker writes
 * the sort lines for a chunk ({@link ProcBuildNodeTableX.NodeHashTmpStream}, with its
 * own node cache, see {@link #cacheSize()}) to a buffer, then appends the whole buffer
 * to the sort input under a lock. The order of nodes does not matter to the sort.
 */
final class ParallelNodeParser {

    /**
     * Node cache entries for all workers together, 3 million unless the system property
     * {@code jena.xloader.nodes.cacheSize} is set. Each worker's cache is an equal share,
     * at most {@link ProcBuildNodeTableX.NodeHashTmpStream#CacheSize} (500,000, as when
     * parsing on one thread): up to 6 workers have 500,000 each, more workers share the
     * total, so memory does not grow with {@code --parse-threads}.
     * 0 (the default): from the system property, read by {@link #cacheSize()}.
     */
    static int CacheSize = 0;

    /** {@link #CacheSize}, or the system property; a bad property value throws {@link TDBException}. */
    static int cacheSize() {
        return CacheSize > 0 ? CacheSize : cacheSize(System.getProperty("jena.xloader.nodes.cacheSize"));
    }

    static int cacheSize(String value) {
        return BulkLoaderX.cacheSize("jena.xloader.nodes.cacheSize", value, 3_000_000);
    }

    /** Entries in each of {@code threads} workers' caches, from {@code total}. */
    static int workerCacheSize(int total, int threads) {
        return Math.min(ProcBuildNodeTableX.NodeHashTmpStream.CacheSize, total / threads);
    }

    /**
     * One node cache of {@link #cacheSize()} shared by all workers (a concurrent Caffeine
     * cache), instead of one each, if the system property
     * {@code jena.xloader.nodes.sharedCache=true} is set (for comparison). Two workers may
     * both miss a node and both write it: sort --unique removes the duplicate.
     * On lexemes with 6 workers (2026-10-06), a shared cache of 500,000 sent 12% fewer node
     * lines to sort, but parsing took about 10 s (11%) longer, which the term index did
     * not make up.
     */
    static boolean SharedCache = "true".equals(System.getProperty("jena.xloader.nodes.sharedCache"));

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
        int total = cacheSize();
        CacheSet<Node> shared = SharedCache ? CacheFactory.createCacheSet(total) : null;
        int perWorker = workerCacheSize(total, threads);
        if ( shared != null )
            FmtLog.info(BulkLoaderX.LOG_Nodes, "Node cache: %,d entries, shared by %d workers", total, threads);
        else
            FmtLog.info(BulkLoaderX.LOG_Nodes, "Node cache: %,d entries for each of %d workers", perWorker, threads);
        return ParallelParser.parse(input, lang, baseIRI, seed, threads, chunkSize, cancelled, progress,
                                    () -> new NodeWorker(output, shared != null ? shared
                                            : CacheFactory.createCacheSet(perWorker), lines),
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
