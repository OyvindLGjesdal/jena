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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.function.BiPredicate;

import org.junit.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;

/**
 * GH-4300: string equality as in {@code NVCompare.sameValueAs} for {@code VSPACE_STRING},
 * standalone: {@code compareTo == 0} (main), the code point loop {@code == 0} (apache/jena#4314),
 * and {@code String.equals}.
 * <p>
 * "equalPairs" never happens in Jena: equal RDF terms take a fast path in {@code sameValueAs}.
 * "randomPairs" (unequal strings) is the case that reaches the comparison.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class TestStringEquality {
    static final int PAIRS = 1 << 16;

    @Param({"utf16", "codepoint-loop", "equals"})
    String impl;

    @Param({"literals", "iris"})
    String data;

    BiPredicate<String, String> eq;
    String[] left;
    String[] right;
    String[] leftCopy;

    @Setup(Level.Trial)
    public void setup() throws IOException {
        eq = switch (impl) {
            case "utf16"          -> (a, b) -> StringComparators.compareUTF16(a, b) == 0;
            case "codepoint-loop" -> (a, b) -> StringComparators.compareCodePointLoop(a, b) == 0;
            case "equals"         -> String::equals;
            default               -> throw new IllegalArgumentException(impl);
        };
        String[] all = StringCompareData.load(data);
        Random rnd = new Random(42);
        left = new String[PAIRS];
        right = new String[PAIRS];
        leftCopy = new String[PAIRS];
        for ( int i = 0 ; i < PAIRS ; i++ ) {
            left[i] = all[rnd.nextInt(all.length)];
            right[i] = all[rnd.nextInt(all.length)];
            leftCopy[i] = new String(left[i].toCharArray());
        }
    }

    /** Equal content: the whole string must be checked. */
    @Benchmark
    @OperationsPerInvocation(PAIRS)
    public int equalPairs() {
        int n = 0;
        for ( int i = 0 ; i < PAIRS ; i++ )
            if ( eq.test(left[i], leftCopy[i]) )
                n++;
        return n;
    }

    /** Two random sampled strings: almost always unequal. */
    @Benchmark
    @OperationsPerInvocation(PAIRS)
    public int randomPairs() {
        int n = 0;
        for ( int i = 0 ; i < PAIRS ; i++ )
            if ( eq.test(left[i], right[i]) )
                n++;
        return n;
    }

    @Test
    public void benchmark() throws Exception {
        assumeTrue("Set -D" + StringCompareData.PROPERTY, StringCompareData.directory() != null);
        var results = new Runner(StringCompareData.options(this.getClass()).build()).run();
        assertNotNull(results);
    }
}
