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

package org.apache.jena.sparql.expr;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.junit.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;

/**
 * GH-4300: string comparison variants on strings sampled from the Wikidata lexemes dump.
 * Standalone copies of the comparison, without {@code NodeValue}. See README.md.
 * <p>
 * "equalPairs" calls the comparator directly. In Jena, equal RDF terms take a fast path in
 * {@code NVCompare} and never reach {@code XSDFuncOp.compareString}.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
public class TestStringComparators {
    static final int PAIRS = 1 << 16;
    static final int SORT_SIZE = 100_000;

    @Param({"utf16", "codepoint-loop", "fixup", "guard", "char-loop"})
    String impl;

    @Param({"literals", "iris"})
    String data;

    Comparator<String> cmp;
    String[] left;
    String[] right;
    String[] leftCopy;
    String[] sortInput;

    static Comparator<String> comparator(String impl) {
        return switch (impl) {
            case "utf16"          -> StringComparators::compareUTF16;
            case "codepoint-loop" -> StringComparators::compareCodePointLoop;
            case "fixup"          -> StringComparators::compareFixup;
            case "guard"          -> StringComparators::compareGuard;
            case "char-loop"      -> StringComparators::compareCharLoop;
            default               -> throw new IllegalArgumentException(impl);
        };
    }

    @Setup(Level.Trial)
    public void setup() throws IOException {
        cmp = comparator(impl);
        String[] all = StringCompareData.load(data);
        Random rnd = new Random(42);
        left = new String[PAIRS];
        right = new String[PAIRS];
        leftCopy = new String[PAIRS];
        for ( int i = 0 ; i < PAIRS ; i++ ) {
            left[i] = all[rnd.nextInt(all.length)];
            right[i] = all[rnd.nextInt(all.length)];
            // Same content, separate backing array: no identity shortcut.
            leftCopy[i] = new String(left[i].toCharArray());
        }
        sortInput = new String[SORT_SIZE];
        for ( int i = 0 ; i < SORT_SIZE ; i++ )
            sortInput[i] = all[rnd.nextInt(all.length)];
    }

    /** Two random strings from the sample. */
    @Benchmark
    @OperationsPerInvocation(PAIRS)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public int randomPairs() {
        int sum = 0;
        for ( int i = 0 ; i < PAIRS ; i++ )
            sum += Integer.signum(cmp.compare(left[i], right[i]));
        return sum;
    }

    /** Equal content, separate String objects: the comparison scans the whole string. */
    @Benchmark
    @OperationsPerInvocation(PAIRS)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public int equalPairs() {
        int sum = 0;
        for ( int i = 0 ; i < PAIRS ; i++ )
            sum += Integer.signum(cmp.compare(left[i], leftCopy[i]));
        return sum;
    }

    /** Sort 100,000 sampled strings. */
    @Benchmark
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public String[] sort() {
        String[] a = sortInput.clone();
        Arrays.sort(a, cmp);
        return a;
    }

    /** The code point variants agree with the reference, including around the surrogate range. */
    @Test
    public void variantsAgree() {
        String[] wellFormed = { "a", "z", "é", "一", "퟿", "", "�", "￿",
                                "𝄞", "𐀀", "􏿿" };
        String[] loneSurrogates = { "\uD834", "\uDD1E" };
        Random rnd = new Random(3);
        for ( int i = 0 ; i < 200_000 ; i++ ) {
            boolean lone = rnd.nextBoolean();
            String a = randomString(wellFormed, loneSurrogates, lone, rnd);
            String b = rnd.nextInt(4) == 0 ? a + randomString(wellFormed, loneSurrogates, lone, rnd)
                                           : randomString(wellFormed, loneSurrogates, lone, rnd);
            int expected = Integer.signum(StringComparators.compareReference(a, b));
            for ( String impl : new String[] {"codepoint-loop", "guard", "char-loop"} )
                assertEquals(impl, expected, Integer.signum(comparator(impl).compare(a, b)));
            // fixup follows ICU and differs from code point order only for lone surrogates.
            if ( !lone )
                assertEquals("fixup", expected, Integer.signum(StringComparators.compareFixup(a, b)));
        }
    }

    private static String randomString(String[] wellFormed, String[] lone, boolean withLone, Random rnd) {
        StringBuilder sb = new StringBuilder();
        int n = rnd.nextInt(6);
        for ( int i = 0 ; i < n ; i++ ) {
            if ( withLone && rnd.nextInt(6) == 0 )
                sb.append(lone[rnd.nextInt(lone.length)]);
            else
                sb.append(wellFormed[rnd.nextInt(wellFormed.length)]);
        }
        return sb.toString();
    }

    @Test
    public void benchmark() throws Exception {
        assumeTrue("Set -D" + StringCompareData.PROPERTY, StringCompareData.directory() != null);
        var results = new Runner(StringCompareData.options(this.getClass()).build()).run();
        assertNotNull(results);
    }
}
