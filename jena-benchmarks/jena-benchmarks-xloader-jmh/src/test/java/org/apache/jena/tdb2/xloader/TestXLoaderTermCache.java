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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.thrift.TException;
import org.apache.thrift.TSerializer;
import org.apache.thrift.protocol.TCompactProtocol;
import org.junit.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.system.AsyncParser;
import org.apache.jena.riot.system.ErrorHandlerFactory;
import org.apache.jena.riot.system.ParserProfile;
import org.apache.jena.riot.system.RiotLib;
import org.apache.jena.riot.thrift.ThriftConvert;
import org.apache.jena.riot.thrift.wire.RDF_Term;
import org.apache.jena.riot.tokens.Token;
import org.apache.jena.riot.tokens.TokenizerText;
import org.apache.jena.tdb2.lib.NodeLib;
import org.apache.jena.tdb2.store.Hash;
import org.apache.jena.tdb2.store.NodeId;
import org.apache.jena.tdb2.sys.SystemTDB;

/**
 * An alternative N-Triples front end for the node table stage: a cache keyed on the raw
 * bytes of each term, checked before the term is tokenized or turned into a {@link Node}.
 * <p>
 * Each invocation reads the whole file named by {@code XLOADER_JMH_DATA} and writes the
 * node table stage's sort input (hash and Thrift term in hex) to a buffered null stream:
 * <ul>
 * <li>{@code nodeTableAsync}: as the node table stage does now: {@link AsyncParser} into
 * {@link ProcBuildNodeTableX.NodeHashTmpStream} (its 500,000-entry Node cache).</li>
 * <li>{@code termCache}: one thread. A byte scanner finds each term; a direct-mapped cache
 * of 2^20 slots keyed on the term's bytes skips terms already seen. Only on a miss is the
 * term tokenized ({@link TokenizerText}), made into a Node by an N-Triples
 * {@link ParserProfile}, hashed and written, as {@code NodeHashTmpStream} does.</li>
 * <li>{@code termCacheIri}: the same, but a missed IRI without escapes goes straight to
 * {@link ParserProfile#createURI} (which checks it) without the tokenizer.</li>
 * </ul>
 * Equal term text is always the same node in N-Triples (no prefixes or base; blank node
 * labels within one parse); different escapes for one term only cause extra misses.
 * Setup checks that both write the same set of node hashes (blank nodes excluded: they
 * get new labels in every parse) and reports the cache hit rate.
 * <p>
 * This is a prototype of an alternative parser, not a replacement for RIOT: it handles
 * N-Triples only and relies on the tokenizer for escapes and errors on a miss.
 */
@State(Scope.Benchmark)
public class TestXLoaderTermCache {

    private static final int CACHE_BITS = 20;

    private String datafile;

    @Setup(Level.Trial)
    public void setup() throws IOException {
        datafile = XLoaderJmh.dataFile();
        HashRecorder expected = new HashRecorder();
        AsyncParser.asyncParse(datafile, new ProcBuildNodeTableX.NodeHashTmpStream(expected));
        for ( boolean fast : new boolean[] {false, true} ) {
            HashRecorder actual = new HashRecorder();
            TermCacheLoader loader = new TermCacheLoader(actual, fast);
            try ( InputStream in = IO.openFile(datafile) ) {
                loader.run(in);
            }
            String name = fast ? "termCacheIri" : "termCache";
            System.out.printf("%n# %s: %,d terms, %,d cache hits (%.1f%%), %,d nodes written%n", name,
                              loader.terms, loader.hits, 100.0 * loader.hits / loader.terms, loader.written);
            if ( !expected.hashes.equals(actual.hashes) ) {
                throw new IllegalStateException("Node hashes differ: nodeTableAsync " + expected.hashes.size()
                                                + ", " + name + " " + actual.hashes.size());
            }
        }
    }

    @Benchmark
    public void nodeTableAsync() {
        OutputStream output = IO.ensureBuffered(OutputStream.nullOutputStream());
        var stream = new ProcBuildNodeTableX.NodeHashTmpStream(output);
        stream.start();
        AsyncParser.asyncParse(datafile, stream);
        stream.finish();
    }

    @Benchmark
    public long termCache() throws IOException {
        return termCache(false);
    }

    @Benchmark
    public long termCacheIri() throws IOException {
        return termCache(true);
    }

    private long termCache(boolean iriFastPath) throws IOException {
        OutputStream output = IO.ensureBuffered(OutputStream.nullOutputStream());
        TermCacheLoader loader = new TermCacheLoader(output, iriFastPath);
        try ( InputStream in = IO.openFile(datafile) ) {
            loader.run(in);
        }
        output.flush();
        return loader.written;
    }

    /** Scans N-Triples bytes; looks each term up in the byte cache; handles misses. */
    private static final class TermCacheLoader {
        private final OutputStream output;
        // N-Triples does not resolve IRIs; the base is required but unused (RDFParser passes the file's IRI).
        private final ParserProfile profile =
                RiotLib.profile(Lang.NTRIPLES, "file:///xloader-jmh", ErrorHandlerFactory.errorHandlerStd);
        private final TSerializer serializer;
        private final Hash hash = new Hash(SystemTDB.LenNodeHash);

        // Direct-mapped cache: one key per slot, replaced on a collision.
        private final byte[][] keys = new byte[1 << CACHE_BITS][];
        private final int[] keyHashes = new int[1 << CACHE_BITS];
        private final int mask = (1 << CACHE_BITS) - 1;

        private byte[] buf = new byte[128 * 1024];
        private int pos = 0;
        private int end = 0;
        private InputStream in;
        private int lastShift = 0;

        long terms = 0;
        long hits = 0;
        long written = 0;

        private final boolean iriFastPath;

        TermCacheLoader(OutputStream output, boolean iriFastPath) {
            this.output = output;
            this.iriFastPath = iriFastPath;
            try {
                this.serializer = new TSerializer(new TCompactProtocol.Factory());
            } catch (TException ex) {
                throw new IllegalStateException(ex);
            }
        }

        void run(InputStream input) throws IOException {
            this.in = input;
            for ( ;; ) {
                if ( !skipWhitespace() )
                    return;
                byte b = buf[pos];
                int tokenEnd = switch ( b ) {
                    case '<' -> scanTo(pos + 1, (byte)'>') + 1;
                    case '"' -> scanLiteral();
                    case '_' -> scanName(pos + 2);
                    case '.' -> -1;
                    default -> throw new IOException("Unexpected byte " + (b & 0xFF));
                };
                if ( tokenEnd < 0 ) {
                    pos++;
                    continue;
                }
                term(pos, tokenEnd);
                pos = tokenEnd;
            }
        }

        private void term(int start, int tokenEnd) throws IOException {
            terms++;
            int len = tokenEnd - start;
            int h = hashBytes(buf, start, len);
            int slot = (h ^ (h >>> CACHE_BITS)) & mask;
            byte[] k = keys[slot];
            if ( k != null && keyHashes[slot] == h && Arrays.equals(k, 0, k.length, buf, start, tokenEnd) ) {
                hits++;
                return;
            }
            keys[slot] = Arrays.copyOfRange(buf, start, tokenEnd);
            keyHashes[slot] = h;
            Node node;
            if ( iriFastPath && buf[start] == '<' && !contains(buf, start, tokenEnd, (byte)'\\') ) {
                // An IRI without escapes: straight to the profile (which checks it), no tokenizer.
                node = profile.createURI(new String(buf, start + 1, len - 2, StandardCharsets.UTF_8), -1, -1);
            } else {
                Token token = TokenizerText.fromString(new String(buf, start, len, StandardCharsets.UTF_8)).next();
                node = profile.create(null, token);
            }
            miss(node);
        }

        private static boolean contains(byte[] b, int from, int to, byte x) {
            for ( int i = from ; i < to ; i++ )
                if ( b[i] == x )
                    return true;
            return false;
        }

        /** As NodeHashTmpStream.node, without its Node cache. */
        private void miss(Node node) throws IOException {
            if ( NodeId.inline(node) != null )
                return;
            NodeLib.setHash(hash, node);
            try {
                byte[] k = hash.getBytes();
                RDF_Term term = ThriftConvert.convert(node, false);
                byte[] tBytes = serializer.serialize(term);
                for ( byte x : k )
                    ProcBuildNodeTableX.hexWrite(output, x);
                output.write(' ');
                for ( byte x : tBytes )
                    ProcBuildNodeTableX.hexWrite(output, x);
                output.write('\n');
                written++;
            } catch (TException ex) {
                throw new IOException(ex);
            }
        }

        private static int hashBytes(byte[] b, int off, int len) {
            int h = 0x9E3779B9;
            for ( int i = off ; i < off + len ; i++ )
                h = 31 * h + b[i];
            return h ^ (h >>> 16);
        }

        // ---- Byte scanning, as TestTokenizerScan's ByteScanner (plain loop search).

        private boolean skipWhitespace() throws IOException {
            for ( ;; ) {
                if ( pos == end && !fill() )
                    return false;
                byte b = buf[pos];
                if ( b == ' ' || b == '\t' || b == '\r' || b == '\n' )
                    pos++;
                else if ( b == '#' )
                    pos = scanTo(pos, (byte)'\n');
                else
                    return true;
            }
        }

        private int scanTo(int from, byte stop) throws IOException {
            int i = from;
            for ( ;; ) {
                for ( ; i < end ; i++ )
                    if ( buf[i] == stop )
                        return i;
                i -= more();
                if ( i >= end )
                    throw new IOException("Unterminated term");
            }
        }

        private int scanLiteral() throws IOException {
            int i = pos + 1;
            for ( ;; ) {
                while ( i < end ) {
                    byte c = buf[i];
                    if ( c == '\\' ) {
                        i += 2;
                        continue;
                    }
                    if ( c == '"' )
                        return suffix(i + 1);
                    i++;
                }
                i -= more();
                if ( i >= end )
                    throw new IOException("Unterminated literal");
            }
        }

        private int suffix(int i) throws IOException {
            if ( !ensure(i, 2) )
                return i;
            i -= lastShift;
            if ( buf[i] == '@' )
                return scanName(i + 1);
            if ( buf[i] == '^' && buf[i + 1] == '^' )
                return scanTo(i + 3, (byte)'>') + 1;
            return i;
        }

        private int scanName(int from) throws IOException {
            int i = from;
            for ( ;; ) {
                while ( i < end ) {
                    byte b = buf[i];
                    if ( b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '.' && isTerminatingDot(i) )
                        return i;
                    i++;
                }
                i -= more();
                if ( i >= end )
                    return end;
            }
        }

        private boolean isTerminatingDot(int i) {
            if ( i + 1 >= end )
                return true;
            byte b = buf[i + 1];
            return b == ' ' || b == '\t' || b == '\n' || b == '\r';
        }

        private boolean ensure(int i, int n) throws IOException {
            lastShift = 0;
            while ( end - i < n ) {
                int before = end - i;
                int shift = more();
                lastShift += shift;
                i -= shift;
                if ( end - i == before )
                    return false;
            }
            return true;
        }

        private boolean fill() throws IOException {
            pos = 0;
            end = in.readNBytes(buf, 0, buf.length);
            return end > 0;
        }

        private int more() throws IOException {
            int shift = pos;
            int keep = end - pos;
            if ( keep == buf.length ) {
                buf = Arrays.copyOf(buf, buf.length * 2);
            } else if ( shift > 0 ) {
                System.arraycopy(buf, pos, buf, 0, keep);
            }
            pos = 0;
            end = keep;
            int n = in.readNBytes(buf, end, buf.length - end);
            if ( n > 0 )
                end += n;
            return shift;
        }
    }

    /** Collects the hashes written, without blank nodes. */
    private static final class HashRecorder extends OutputStream {
        // Hex of the first Thrift byte of a blank node term (the union field header).
        private static final String BLANK_PREFIX = blankPrefix();
        final Set<String> hashes = new HashSet<>();
        private final StringBuilder line = new StringBuilder(256);

        @Override
        public void write(int b) {
            if ( b != '\n' ) {
                line.append((char)b);
                return;
            }
            String s = line.toString();
            line.setLength(0);
            int space = s.indexOf(' ');
            if ( !isBlankNode(s.substring(space + 1)) )
                hashes.add(s.substring(0, space));
        }

        private static boolean isBlankNode(String thriftHex) {
            return thriftHex.startsWith(BLANK_PREFIX);
        }

        private static String blankPrefix() {
            try {
                byte[] b = new TSerializer(new TCompactProtocol.Factory())
                        .serialize(ThriftConvert.convert(NodeFactory.createBlankNode(), false));
                return String.format("%02X", b[0] & 0xFF);
            } catch (TException ex) {
                throw new IllegalStateException(ex);
            }
        }
    }

    @Test
    public void benchmark() throws Exception {
        // Fail here, before JMH forks, if the data file is missing.
        XLoaderJmh.dataFile();
        new Runner(XLoaderJmh.options(TestXLoaderTermCache.class).build()).run();
    }
}
