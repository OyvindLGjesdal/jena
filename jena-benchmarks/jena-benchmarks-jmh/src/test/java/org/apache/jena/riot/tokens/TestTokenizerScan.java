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
package org.apache.jena.riot.tokens;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeUnit;

import org.junit.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.BenchmarkParams;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.atlas.io.PeekReader;

/**
 * How much could tokenizing N-Triples gain from scanning whole tokens in the character
 * buffer, instead of reading one character at a time through {@link PeekReader}?
 * <p>
 * Each invocation reads the whole N-Triples file (for example {@code .nt.gz}) named by
 * the environment variable {@value #DATA_ENV}:
 * <ul>
 * <li>{@code tokenizer}: {@link TokenizerText}, as the N-Triples parser uses it (no nodes created).</li>
 * <li>{@code peekReader}: {@link PeekReader#readChar()} for every character; the floor
 * for any tokenizer built on it.</li>
 * <li>{@code bulkScan}: a minimal scanner that finds the end of each IRI, literal, blank
 * node label and language tag or datatype within a 128K char buffer and copies each image
 * out as a String. It does not decode escapes or check anything, so it is a lower bound
 * for a bulk-scanning tokenizer, not a replacement.</li>
 * <li>{@code bytesScalar}, {@code bytesSwar}, {@code bytesVector}: the same scanning on the
 * undecoded UTF-8 bytes, decoding only each token image. They differ only in how they
 * search for {@code >}, {@code "} and {@code \}: a plain loop, 8 bytes at a time in a
 * {@code long} (SWAR), or the incubating Vector API ({@link VectorByteFinder}).</li>
 * </ul>
 * Setup checks that the variant being run counts the same tokens as {@code tokenizer}.
 * The Vector API variant needs {@code --add-modules jdk.incubator.vector}, which the
 * module's compiler settings and {@link #benchmark()} pass.
 */
@State(Scope.Benchmark)
public class TestTokenizerScan {

    /** Environment variable naming the N-Triples file to read. */
    public static final String DATA_ENV = "RIOT_JMH_DATA";

    private String datafile;

    @Setup(Level.Trial)
    public void setup(BenchmarkParams params) throws IOException {
        datafile = dataFile();
        String name = params.getBenchmark().substring(params.getBenchmark().lastIndexOf('.') + 1);
        long actual = switch (name) {
            case "bulkScan" -> bulkScan(null);
            case "bytesScalar" -> bytesScalar(null);
            case "bytesSwar" -> bytesSwar(null);
            case "bytesVector" -> bytesVector(null);
            default -> -1;
        };
        if ( actual < 0 )
            return;
        long expected = tokenizer(null);
        if ( expected != actual )
            throw new IllegalStateException("Token counts differ: tokenizer " + expected + ", " + name + " " + actual);
    }

    @Benchmark
    public long tokenizer(Blackhole bh) {
        Tokenizer tokenizer = TokenizerText.create().source(PeekReader.makeUTF8(IO.openFile(datafile))).build();
        long count = 0;
        try {
            while ( tokenizer.hasNext() ) {
                Token t = tokenizer.next();
                if ( bh != null )
                    bh.consume(t);
                count++;
            }
        } finally {
            tokenizer.close();
        }
        return count;
    }

    @Benchmark
    public long peekReader() throws IOException {
        long count = 0;
        try ( PeekReader in = PeekReader.makeUTF8(IO.openFile(datafile)) ) {
            while ( in.readChar() != IO.EOF )
                count++;
        }
        return count;
    }

    @Benchmark
    public long bulkScan(Blackhole bh) throws IOException {
        try ( Reader in = IO.asUTF8(IO.openFile(datafile)) ) {
            return new Scanner(in, bh).run();
        }
    }

    @Benchmark
    public long bytesScalar(Blackhole bh) throws IOException {
        return bytes(new ScalarByteFinder(), bh);
    }

    @Benchmark
    public long bytesSwar(Blackhole bh) throws IOException {
        return bytes(new SwarByteFinder(), bh);
    }

    @Benchmark
    public long bytesVector(Blackhole bh) throws IOException {
        return bytes(new VectorByteFinder(), bh);
    }

    private long bytes(ByteFinder finder, Blackhole bh) throws IOException {
        try ( InputStream in = IO.openFile(datafile) ) {
            return new ByteScanner(in, finder, bh).run();
        }
    }

    /** Finds the first of one or two byte values in {@code bytes[from, to)}, or -1. */
    interface ByteFinder {
        int find(byte[] bytes, int from, int to, byte target);
        int find2(byte[] bytes, int from, int to, byte target1, byte target2);
    }

    static final class ScalarByteFinder implements ByteFinder {
        @Override
        public int find(byte[] bytes, int from, int to, byte target) {
            for ( int i = from ; i < to ; i++ )
                if ( bytes[i] == target )
                    return i;
            return -1;
        }

        @Override
        public int find2(byte[] bytes, int from, int to, byte target1, byte target2) {
            for ( int i = from ; i < to ; i++ )
                if ( bytes[i] == target1 || bytes[i] == target2 )
                    return i;
            return -1;
        }
    }

    /** SWAR: 8 bytes at a time with long arithmetic; no special JVM support needed. */
    static final class SwarByteFinder implements ByteFinder {
        private static final VarHandle LONG = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);
        private static final long ONES = 0x0101010101010101L;
        private static final long HIGHS = 0x8080808080808080L;

        private static long pattern(byte b) { return (b & 0xFFL) * ONES; }

        // High bit set in each byte of x that is zero. Only bytes above the first zero can
        // be wrong, so the lowest flagged byte is always a true match.
        private static long zeros(long x) { return (x - ONES) & ~x & HIGHS; }

        @Override
        public int find(byte[] bytes, int from, int to, byte target) {
            long p = pattern(target);
            int i = from;
            for ( ; i + 8 <= to ; i += 8 ) {
                long t = zeros((long)LONG.get(bytes, i) ^ p);
                if ( t != 0 )
                    return i + (Long.numberOfTrailingZeros(t) >>> 3);
            }
            for ( ; i < to ; i++ )
                if ( bytes[i] == target )
                    return i;
            return -1;
        }

        @Override
        public int find2(byte[] bytes, int from, int to, byte target1, byte target2) {
            long p1 = pattern(target1);
            long p2 = pattern(target2);
            int i = from;
            for ( ; i + 8 <= to ; i += 8 ) {
                long w = (long)LONG.get(bytes, i);
                long t = zeros(w ^ p1) | zeros(w ^ p2);
                if ( t != 0 )
                    return i + (Long.numberOfTrailingZeros(t) >>> 3);
            }
            for ( ; i < to ; i++ )
                if ( bytes[i] == target1 || bytes[i] == target2 )
                    return i;
            return -1;
        }
    }

    /** {@link Scanner} on UTF-8 bytes, with a pluggable search for token ends. */
    private static final class ByteScanner {
        private final InputStream in;
        private final ByteFinder finder;
        private final Blackhole bh;
        private byte[] buf = new byte[128 * 1024];
        private int pos = 0;
        private int end = 0;
        private long tokens = 0;
        private long lines = 0;
        private int lastShift = 0;

        ByteScanner(InputStream in, ByteFinder finder, Blackhole bh) {
            this.in = in;
            this.finder = finder;
            this.bh = bh;
        }

        long run() throws IOException {
            for ( ;; ) {
                if ( !skipWhitespace() )
                    return tokens;
                byte b = buf[pos];
                switch ( b ) {
                    case '<' -> emit(scanTo(pos + 1, (byte)'>') + 1);
                    case '"' -> emit(scanLiteral());
                    case '_' -> emit(scanName(pos + 2));
                    case '.' -> emit(pos + 1);
                    default -> throw new IOException("Unexpected byte " + (b & 0xFF) + " near line " + (lines + 1));
                }
            }
        }

        private boolean skipWhitespace() throws IOException {
            for ( ;; ) {
                if ( pos == end && !fill() )
                    return false;
                byte b = buf[pos];
                if ( b == '\n' ) {
                    lines++;
                    pos++;
                } else if ( b == ' ' || b == '\t' || b == '\r' ) {
                    pos++;
                } else if ( b == '#' ) {
                    pos = scanTo(pos, (byte)'\n');
                } else {
                    return true;
                }
            }
        }

        private int scanTo(int from, byte stop) throws IOException {
            int i = from;
            for ( ;; ) {
                int found = i < end ? finder.find(buf, i, end, stop) : -1;
                if ( found >= 0 )
                    return found;
                i = end;
                i -= more();
                if ( i >= end )
                    throw new IOException("Unterminated token near line " + (lines + 1));
            }
        }

        private int scanLiteral() throws IOException {
            int i = pos + 1;
            for ( ;; ) {
                int found = i < end ? finder.find2(buf, i, end, (byte)'"', (byte)'\\') : -1;
                if ( found >= 0 ) {
                    if ( buf[found] == '"' )
                        return suffix(found + 1);
                    i = found + 2;      // Skip the escaped byte.
                    continue;
                }
                i = Math.max(i, end);
                i -= more();
                if ( i >= end )
                    throw new IOException("Unterminated literal near line " + (lines + 1));
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

        private void emit(int tokenEnd) {
            String image = new String(buf, pos, tokenEnd - pos, StandardCharsets.UTF_8);
            if ( bh != null )
                bh.consume(image);
            tokens++;
            pos = tokenEnd;
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
                byte[] bigger = new byte[buf.length * 2];
                System.arraycopy(buf, 0, bigger, 0, keep);
                buf = bigger;
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

    /** Minimal N-Triples token scanner over a char buffer; see the class comment. */
    private static final class Scanner {
        private final Reader in;
        private final Blackhole bh;
        private char[] buf = new char[128 * 1024];
        private int pos = 0;
        private int end = 0;
        private long tokens = 0;
        private long lines = 0;

        Scanner(Reader in, Blackhole bh) {
            this.in = in;
            this.bh = bh;
        }

        long run() throws IOException {
            for ( ;; ) {
                if ( !skipWhitespace() )
                    return tokens;
                char ch = buf[pos];
                switch ( ch ) {
                    case '<' -> emit(scanTo(pos + 1, '>') + 1);
                    case '"' -> emit(scanLiteral());
                    case '_' -> emit(scanName(pos + 2));
                    case '.' -> emit(pos + 1);
                    default -> throw new IOException("Unexpected character '" + ch + "' near line " + (lines + 1));
                }
            }
        }

        /** Skip spaces, newlines and comments; false at end of input. */
        private boolean skipWhitespace() throws IOException {
            for ( ;; ) {
                if ( pos == end && !fill() )
                    return false;
                char ch = buf[pos];
                if ( ch == '\n' ) {
                    lines++;
                    pos++;
                } else if ( ch == ' ' || ch == '\t' || ch == '\r' ) {
                    pos++;
                } else if ( ch == '#' ) {
                    int e = scanTo(pos, '\n');
                    pos = e;
                } else {
                    return true;
                }
            }
        }

        /** Index of the next {@code stop} at or after {@code from}, refilling as needed. */
        private int scanTo(int from, char stop) throws IOException {
            int i = from;
            for ( ;; ) {
                while ( i < end ) {
                    if ( buf[i] == stop )
                        return i;
                    i++;
                }
                i -= more();
                if ( i >= end )
                    throw new IOException("Unterminated token near line " + (lines + 1));
            }
        }

        /** End of a literal, including a language tag or datatype IRI. */
        private int scanLiteral() throws IOException {
            int i = pos + 1;
            for ( ;; ) {
                while ( i < end ) {
                    char c = buf[i];
                    if ( c == '\\' ) {
                        i += 2;
                        continue;
                    }
                    if ( c == '"' ) {
                        i++;
                        return suffix(i);
                    }
                    i++;
                }
                i -= more();
                if ( i >= end )
                    throw new IOException("Unterminated literal near line " + (lines + 1));
            }
        }

        private int suffix(int i) throws IOException {
            if ( !ensure(i, 2) )
                return i;
            i -= lastShift;
            if ( buf[i] == '@' )
                return scanName(i + 1);
            if ( buf[i] == '^' && buf[i + 1] == '^' )
                return scanTo(i + 3, '>') + 1;
            return i;
        }

        /** End of a blank node label or language tag. */
        private int scanName(int from) throws IOException {
            int i = from;
            for ( ;; ) {
                while ( i < end ) {
                    char c = buf[i];
                    if ( c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '.' && isTerminatingDot(i) )
                        return i;
                    i++;
                }
                i -= more();
                if ( i >= end )
                    return end;
            }
        }

        // A '.' ends a label only if followed by whitespace or end of input.
        private boolean isTerminatingDot(int i) {
            return i + 1 >= end || Character.isWhitespace(buf[i + 1]);
        }

        private void emit(int tokenEnd) {
            String image = new String(buf, pos, tokenEnd - pos);
            if ( bh != null )
                bh.consume(image);
            tokens++;
            pos = tokenEnd;
        }

        private int lastShift = 0;

        /** Make {@code n} chars from {@code i} available if possible; sets {@link #lastShift}. */
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

        /** Initial or next block when the buffer is used up. */
        private boolean fill() throws IOException {
            pos = 0;
            end = in.read(buf, 0, buf.length);
            if ( end <= 0 ) {
                end = 0;
                return false;
            }
            return true;
        }

        /**
         * Keep the current token (from {@code pos}) and read more after it.
         * @return how far the chars moved left; nothing more is added at end of input.
         */
        private int more() throws IOException {
            int shift = pos;
            int keep = end - pos;
            if ( keep == buf.length ) {
                char[] bigger = new char[buf.length * 2];
                System.arraycopy(buf, 0, bigger, 0, keep);
                buf = bigger;
            } else if ( shift > 0 ) {
                System.arraycopy(buf, pos, buf, 0, keep);
            }
            pos = 0;
            end = keep;
            int n = in.read(buf, end, buf.length - end);
            if ( n > 0 )
                end += n;
            return shift;
        }
    }

    private static String dataFile() {
        String datafile = System.getenv(DATA_ENV);
        if ( datafile == null || datafile.isBlank() )
            throw new IllegalStateException("Set " + DATA_ENV + " to an N-Triples file, for example a .nt.gz file");
        if ( !Files.isRegularFile(Path.of(datafile)) )
            throw new IllegalStateException(DATA_ENV + ": not a file: " + datafile);
        return datafile;
    }

    @Test
    public void benchmark() throws Exception {
        // Fail here, before JMH forks, if the data file is missing.
        dataFile();
        var opt = new OptionsBuilder()
                .include(TestTokenizerScan.class.getName())
                // Each invocation is one whole pass over the file.
                .mode(Mode.SingleShotTime)
                .timeUnit(TimeUnit.SECONDS)
                .warmupIterations(1)
                .measurementIterations(3)
                .measurementTime(TimeValue.NONE)
                .forks(1)
                .shouldFailOnError(true)
                .shouldDoGC(true)
                .jvmArgs("-Xmx4G", "--add-modules", "jdk.incubator.vector")
                .resultFormat(ResultFormatType.JSON)
                .result(TestTokenizerScan.class.getSimpleName() + "_" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss")) + ".json")
                .build();
        new Runner(opt).run();
    }
}
