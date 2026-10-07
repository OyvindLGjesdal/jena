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

import jdk.incubator.vector.ByteVector;
import jdk.incubator.vector.VectorMask;
import jdk.incubator.vector.VectorSpecies;

/**
 * Byte search with the incubating Vector API ({@code jdk.incubator.vector}).
 * The only class that refers to it: compiling and running it needs
 * {@code --add-modules jdk.incubator.vector}.
 */
final class VectorByteFinder implements TestTokenizerScan.ByteFinder {
    private static final VectorSpecies<Byte> SPECIES = ByteVector.SPECIES_PREFERRED;

    @Override
    public int find(byte[] bytes, int from, int to, byte target) {
        int i = from;
        int bound = from + SPECIES.loopBound(to - from);
        for ( ; i < bound ; i += SPECIES.length() ) {
            VectorMask<Byte> m = ByteVector.fromArray(SPECIES, bytes, i).eq(target);
            if ( m.anyTrue() )
                return i + m.firstTrue();
        }
        for ( ; i < to ; i++ )
            if ( bytes[i] == target )
                return i;
        return -1;
    }

    @Override
    public int find2(byte[] bytes, int from, int to, byte target1, byte target2) {
        int i = from;
        int bound = from + SPECIES.loopBound(to - from);
        for ( ; i < bound ; i += SPECIES.length() ) {
            ByteVector v = ByteVector.fromArray(SPECIES, bytes, i);
            VectorMask<Byte> m = v.eq(target1).or(v.eq(target2));
            if ( m.anyTrue() )
                return i + m.firstTrue();
        }
        for ( ; i < to ; i++ )
            if ( bytes[i] == target1 || bytes[i] == target2 )
                return i;
        return -1;
    }

    @Override
    public String toString() {
        return "Vector API, " + SPECIES.length() + " bytes";
    }
}
