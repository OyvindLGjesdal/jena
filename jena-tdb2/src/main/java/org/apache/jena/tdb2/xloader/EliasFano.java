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

/**
 * A non-decreasing sequence of unsigned 64-bit values with Elias-Fano coding, read-only
 * once built, safe to read from many threads.
 * <p>
 * Each value is split into high bits and low bits. The low bits are packed, a fixed width
 * per value. The high bits are kept as a bit sequence: value {@code i} with high part
 * {@code h} sets bit {@code h + i}, so the values with high part {@code h} are the set
 * bits after the {@code h}-th clear bit. With about {@code log2(n)} high bits, that is
 * about 2 bits a value plus the low bits. Samples of the positions of every 512th set and
 * clear bit make {@link #get} and {@link #indexOf} a short scan.
 */
final class EliasFano {

    static final long NOT_FOUND = -1;
    static final long DUPLICATE = -2;

    private static final int SampleShift = 9;

    private final long size;
    private final int lowBits;
    private final long lowMask;
    private final LongArray upper;
    private final long upperLength;
    private final LongArray low;
    private final long[] onesSamples;
    private final long[] zerosSamples;

    private EliasFano(long size, int lowBits, LongArray upper, long upperLength, LongArray low) {
        this.size = size;
        this.lowBits = lowBits;
        this.lowMask = lowBits == 0 ? 0 : -1L >>> (64 - lowBits);
        this.upper = upper;
        this.upperLength = upperLength;
        this.low = low;
        long zeros = upperLength - size;
        this.onesSamples = new long[(int)((size >>> SampleShift) + 1)];
        this.zerosSamples = new long[(int)((zeros >>> SampleShift) + 1)];
        sample();
    }

    long size() {
        return size;
    }

    /** Approximate memory use in bytes. */
    long bytes() {
        return 8 * (upper.length() + low.length() + onesSamples.length + zerosSamples.length);
    }

    /** The value at {@code index} (0 to size-1). */
    long get(long index) {
        long high = select(true, index) - index;
        return (high << lowBits) | low(index);
    }

    /**
     * The index of {@code value}; {@link #NOT_FOUND} if it is not in the sequence;
     * {@link #DUPLICATE} if it is there more than once.
     */
    long indexOf(long value) {
        long high = value >>> lowBits;
        long target = value & lowMask;
        // The values with this high part are the set bits after the high-th clear bit.
        long pos = ( high == 0 ) ? 0 : select(false, high - 1) + 1;
        long index = pos - high;
        long found = NOT_FOUND;
        for ( ; pos < upperLength && bit(pos) ; pos++, index++ ) {
            long x = low(index);
            if ( x == target ) {
                if ( found != NOT_FOUND )
                    return DUPLICATE;
                found = index;
            } else if ( x > target )
                break;
        }
        return found;
    }

    private boolean bit(long pos) {
        return (upper.get(pos >>> 6) & (1L << pos)) != 0;
    }

    private long low(long index) {
        if ( lowBits == 0 )
            return 0;
        long bitPos = index * lowBits;
        long w = bitPos >>> 6;
        int offset = (int)(bitPos & 63);
        long x = low.get(w) >>> offset;
        if ( offset + lowBits > 64 )
            x |= low.get(w + 1) << (64 - offset);
        return x & lowMask;
    }

    /** The position of the {@code rank}-th (from 0) set ({@code ones}) or clear bit. */
    private long select(boolean ones, long rank) {
        long[] samples = ones ? onesSamples : zerosSamples;
        long start = samples[(int)(rank >>> SampleShift)];
        long r = rank & ((1L << SampleShift) - 1);
        long w = start >>> 6;
        long word = word(ones, w) & (-1L << start);
        for ( ;; ) {
            int c = Long.bitCount(word);
            if ( r < c )
                return (w << 6) + selectInWord(word, (int)r);
            r -= c;
            w++;
            word = word(ones, w);
        }
    }

    private long word(boolean ones, long w) {
        long x = upper.get(w);
        return ones ? x : ~x;
    }

    private static int selectInWord(long word, int r) {
        for ( int i = 0 ; i < r ; i++ )
            word &= word - 1;
        return Long.numberOfTrailingZeros(word);
    }

    private void sample() {
        long ones = 0;
        long zeros = 0;
        long nextOne = 0;
        long nextZero = 0;
        long words = (upperLength + 63) >>> 6;
        for ( long w = 0 ; w < words ; w++ ) {
            long word = upper.get(w);
            int bits = (int)Math.min(64, upperLength - (w << 6));
            long valid = bits == 64 ? -1L : (1L << bits) - 1;
            long clear = ~word & valid;
            int c1 = Long.bitCount(word);
            int c0 = Long.bitCount(clear);
            while ( nextOne < ones + c1 ) {
                onesSamples[(int)(nextOne >>> SampleShift)] = (w << 6) + selectInWord(word, (int)(nextOne - ones));
                nextOne += 1L << SampleShift;
            }
            while ( nextZero < zeros + c0 ) {
                zerosSamples[(int)(nextZero >>> SampleShift)] = (w << 6) + selectInWord(clear, (int)(nextZero - zeros));
                nextZero += 1L << SampleShift;
            }
            ones += c1;
            zeros += c0;
        }
    }

    /** Add the values in non-decreasing (unsigned) order, then {@link #build}. */
    static final class Builder {
        private final long capacity;
        private final int lowBits;
        private final long buckets;
        private final LongArray upper;
        private final LongArray low;
        private long size = 0;
        private long last = 0;

        /**
         * @param capacity at least the number of values
         * @param universeBits every value is below 2^universeBits (1 to 64)
         */
        Builder(long capacity, int universeBits) {
            if ( capacity < 1 )
                throw new IllegalArgumentException("capacity: " + capacity);
            if ( universeBits < 1 || universeBits > 64 )
                throw new IllegalArgumentException("universeBits: " + universeBits);
            this.capacity = capacity;
            int ceilLog2 = 64 - Long.numberOfLeadingZeros(capacity - 1);
            int highBits = Math.max(1, Math.min(universeBits, ceilLog2));
            this.lowBits = universeBits - highBits;
            this.buckets = 1L << highBits;
            this.upper = new LongArray(((capacity + buckets) >>> 6) + 1);
            this.low = new LongArray(((capacity * lowBits) >>> 6) + 2);
        }

        void add(long value) {
            if ( size == capacity )
                throw new IllegalStateException("More values than the capacity " + capacity);
            if ( size > 0 && Long.compareUnsigned(value, last) < 0 )
                throw new IllegalArgumentException("Values not in order");
            if ( lowBits < 64 && (value >>> lowBits) >= buckets )
                throw new IllegalArgumentException("Value outside the universe: " + Long.toUnsignedString(value));
            long high = value >>> lowBits;
            long pos = high + size;
            upper.set(pos >>> 6, upper.get(pos >>> 6) | (1L << pos));
            if ( lowBits > 0 ) {
                long x = value & (-1L >>> (64 - lowBits));
                long bitPos = size * lowBits;
                long w = bitPos >>> 6;
                int offset = (int)(bitPos & 63);
                low.set(w, low.get(w) | (x << offset));
                if ( offset + lowBits > 64 )
                    low.set(w + 1, low.get(w + 1) | (x >>> (64 - offset)));
            }
            last = value;
            size++;
        }

        EliasFano build() {
            // Every bucket ends with a clear bit: buckets clear bits after the last value.
            return new EliasFano(size, lowBits, upper, size + buckets, low);
        }
    }

    /** A long array that can be larger than one Java array. */
    static final class LongArray {
        private static final int ChunkShift = 27;     // 2^27 longs, 1 GB
        private static final long ChunkMask = (1L << ChunkShift) - 1;
        private final long[][] chunks;
        private final long length;

        LongArray(long length) {
            this.length = length;
            int n = (int)((length + ChunkMask) >>> ChunkShift);
            chunks = new long[n][];
            for ( int i = 0 ; i < n ; i++ )
                chunks[i] = new long[(int)Math.min(1L << ChunkShift, length - ((long)i << ChunkShift))];
        }

        long get(long i) {
            return chunks[(int)(i >>> ChunkShift)][(int)(i & ChunkMask)];
        }

        void set(long i, long x) {
            chunks[(int)(i >>> ChunkShift)][(int)(i & ChunkMask)] = x;
        }

        long length() {
            return length;
        }
    }
}
