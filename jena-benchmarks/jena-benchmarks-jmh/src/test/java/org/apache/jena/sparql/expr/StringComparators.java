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

import java.util.Arrays;

/**
 * Standalone string comparisons for GH-4300, without {@code NodeValue}.
 * All return a negative number, zero or a positive number.
 */
public final class StringComparators {
    private StringComparators() {}

    /** UTF-16 code unit order: {@code XSDFuncOp.compareString} before GH-4300. */
    public static int compareUTF16(String s1, String s2) {
        return s1.compareTo(s2);
    }

    /** Code point order: the {@code codePointAt} loop of apache/jena#4314 (commit 61804b5). */
    public static int compareCodePointLoop(String s1, String s2) {
        int i1 = 0;
        int i2 = 0;
        while ( i1 < s1.length() && i2 < s2.length() ) {
            int cp1 = s1.codePointAt(i1);
            int cp2 = s2.codePointAt(i2);
            if ( cp1 != cp2 )
                return Integer.compare(cp1, cp2);
            i1 += Character.charCount(cp1);
            i2 += Character.charCount(cp2);
        }
        return Integer.compare(s1.length() - i1, s2.length() - i2);
    }

    /**
     * Code point order for well-formed UTF-16: compare chars and, at the first difference,
     * when both are &gt;= U+D800, move surrogates above U+E000..U+FFFF (as ICU does).
     * Differs from code point order only for lone surrogates.
     */
    public static int compareFixup(String s1, String s2) {
        int n = Math.min(s1.length(), s2.length());
        for ( int i = 0 ; i < n ; i++ ) {
            int c1 = s1.charAt(i);
            int c2 = s2.charAt(i);
            if ( c1 != c2 ) {
                if ( c1 >= 0xD800 && c2 >= 0xD800 ) {
                    c1 += (c1 >= 0xE000) ? -0x800 : 0x2000;
                    c2 += (c2 >= 0xE000) ? -0x800 : 0x2000;
                }
                return c1 - c2;
            }
        }
        return s1.length() - s2.length();
    }

    /**
     * Code point order: {@code String.compareTo}, falling back to the code point loop only
     * when a string contains a surrogate pair. {@code codePointCount} is O(1) for Latin-1 strings.
     */
    public static int compareGuard(String s1, String s2) {
        int c = s1.compareTo(s2);
        if ( c == 0 || ( noSurrogatePairs(s1) && noSurrogatePairs(s2) ) )
            return c;
        return compareCodePointLoop(s1, s2);
    }

    private static boolean noSurrogatePairs(String s) {
        return s.codePointCount(0, s.length()) == s.length();
    }

    /**
     * Code point order: a char loop that decodes code points only at the first difference,
     * when both chars are &gt;= U+D800.
     */
    public static int compareCharLoop(String s1, String s2) {
        int n = Math.min(s1.length(), s2.length());
        for ( int i = 0 ; i < n ; i++ ) {
            char c1 = s1.charAt(i);
            char c2 = s2.charAt(i);
            if ( c1 != c2 ) {
                if ( c1 >= 0xD800 && c2 >= 0xD800 ) {
                    // Step back when a differing char completes a surrogate pair
                    // with the shared high surrogate before it.
                    int j = i;
                    if ( i > 0 && Character.isHighSurrogate(s1.charAt(i - 1))
                         && ( Character.isLowSurrogate(c1) || Character.isLowSurrogate(c2) ) )
                        j = i - 1;
                    return Integer.compare(s1.codePointAt(j), s2.codePointAt(j));
                }
                return c1 - c2;
            }
        }
        return s1.length() - s2.length();
    }

    /** Reference for code point order, for checking the others. */
    public static int compareReference(String s1, String s2) {
        return Arrays.compare(s1.codePoints().toArray(), s2.codePoints().toArray());
    }
}
