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
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.junit.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;

import org.apache.jena.graph.NodeFactory;

/**
 * GH-4300: string comparisons through Jena's {@code NodeValue}, on values sampled from the
 * Wikidata lexemes dump. This uses whatever jena-arq is on the classpath: run it on main and
 * on a branch with the change to compare them. See README.md.
 * <ul>
 * <li>iri: IRI nodes. {@code ORDER BY} orders them with {@code NodeCmp}, not {@code XSDFuncOp.compareString}.</li>
 * <li>iristr: the same IRI text as {@code xsd:string}, like {@code STR(?iri)}: long shared prefixes.</li>
 * <li>string: lexeme literal text as {@code xsd:string}.</li>
 * <li>lang: lexeme literals with their language tags; pairs share a tag.</li>
 * </ul>
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
public class TestNodeValueStringCompare {
    static final int PAIRS = 1 << 16;
    static final int SORT_SIZE = 100_000;

    @Param({"iri", "iristr", "string", "lang"})
    String data;

    NodeValue[] left;
    NodeValue[] right;      // for lang: same language tag as left
    NodeValue[] leftCopy;   // equal value, separate objects and strings
    NodeValue[] sortInput;

    @Setup(Level.Trial)
    public void setup() throws IOException {
        Random rnd = new Random(42);
        left = new NodeValue[PAIRS];
        right = new NodeValue[PAIRS];
        leftCopy = new NodeValue[PAIRS];
        sortInput = new NodeValue[SORT_SIZE];
        if ( data.equals("lang") ) {
            String[] raw = StringCompareData.load("langlits");
            int n = raw.length / 2;
            Map<String, List<Integer>> byTag = new HashMap<>();
            for ( int i = 0 ; i < n ; i++ )
                byTag.computeIfAbsent(raw[2 * i], k -> new ArrayList<>()).add(i);
            for ( int k = 0 ; k < PAIRS ; k++ ) {
                int i = rnd.nextInt(n);
                List<Integer> sameTag = byTag.get(raw[2 * i]);
                int j = sameTag.get(rnd.nextInt(sameTag.size()));
                left[k] = lang(raw[2 * i + 1], raw[2 * i]);
                right[k] = lang(raw[2 * j + 1], raw[2 * j]);
                leftCopy[k] = lang(copy(raw[2 * i + 1]), copy(raw[2 * i]));
            }
            for ( int k = 0 ; k < SORT_SIZE ; k++ ) {
                int i = rnd.nextInt(n);
                sortInput[k] = lang(raw[2 * i + 1], raw[2 * i]);
            }
            return;
        }
        String[] all = StringCompareData.load(data.startsWith("iri") ? "iris" : "literals");
        for ( int k = 0 ; k < PAIRS ; k++ ) {
            String s = all[rnd.nextInt(all.length)];
            left[k] = make(s);
            right[k] = make(all[rnd.nextInt(all.length)]);
            leftCopy[k] = make(copy(s));
        }
        for ( int k = 0 ; k < SORT_SIZE ; k++ )
            sortInput[k] = make(all[rnd.nextInt(all.length)]);
    }

    private static String copy(String s) {
        return new String(s.toCharArray());
    }

    private static NodeValue lang(String text, String tag) {
        return NodeValue.makeNode(NodeFactory.createLiteralLang(text, tag));
    }

    private NodeValue make(String s) {
        return data.equals("iri") ? NodeValue.makeNode(NodeFactory.createURI(s)) : NodeValue.makeString(s);
    }

    /** ORDER BY: {@code NodeValue.compareAlways}, as {@code BindingComparator} uses it. */
    @Benchmark
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public NodeValue[] sort() {
        NodeValue[] a = sortInput.clone();
        Arrays.sort(a, NodeValue::compareAlways);
        return a;
    }

    /** One ORDER BY comparison on two random values. */
    @Benchmark
    @OperationsPerInvocation(PAIRS)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public int compareAlwaysPairs() {
        int sum = 0;
        for ( int i = 0 ; i < PAIRS ; i++ )
            sum += NodeValue.compareAlways(left[i], right[i]);
        return sum;
    }

    /** {@code <} and {@code >}: {@code NodeValue.compare}. IRIs are not comparable with {@code <}, so "iri" uses compareAlways. */
    @Benchmark
    @OperationsPerInvocation(PAIRS)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public int comparePairs() {
        int sum = 0;
        if ( data.equals("iri") ) {
            for ( int i = 0 ; i < PAIRS ; i++ )
                sum += NodeValue.compareAlways(left[i], right[i]);
            return sum;
        }
        for ( int i = 0 ; i < PAIRS ; i++ )
            sum += NodeValue.compare(left[i], right[i]);
        return sum;
    }

    /** {@code =} on equal values: the same-term fast path in {@code sameValueAs}. */
    @Benchmark
    @OperationsPerInvocation(PAIRS)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public int equalPairs() {
        int sum = 0;
        for ( int i = 0 ; i < PAIRS ; i++ )
            if ( NodeValue.sameValueAs(left[i], leftCopy[i]) )
                sum++;
        return sum;
    }

    /** {@code =} on random, almost always unequal values: for strings this reaches {@code XSDFuncOp.compareString}. */
    @Benchmark
    @OperationsPerInvocation(PAIRS)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public int unequalPairs() {
        int sum = 0;
        for ( int i = 0 ; i < PAIRS ; i++ )
            if ( NodeValue.sameValueAs(left[i], right[i]) )
                sum++;
        return sum;
    }

    @Test
    public void benchmark() throws Exception {
        assumeTrue("Set -D" + StringCompareData.PROPERTY, StringCompareData.directory() != null);
        var results = new Runner(StringCompareData.options(this.getClass()).build()).run();
        assertNotNull(results);
    }
}
