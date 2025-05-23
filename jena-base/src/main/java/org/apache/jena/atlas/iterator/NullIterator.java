/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.jena.atlas.iterator;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.function.Consumer;

/**
 *  Null Iterator - also guaranteed shareable and immutable
 *  <p>
 *  @deprecated Use {@link Iter#nullIterator()}.
 */
@Deprecated
public class NullIterator<T> implements Iterator<T> {

    public static <X> NullIterator<X> create(){ return new NullIterator<>(); }

    private NullIterator() {}

    @Override
    public boolean hasNext() {
        return false;
    }

    @Override
    public T next() {
        throw new NoSuchElementException("NullIterator.next");
    }

    @Override
    public void forEachRemaining(Consumer<? super T> action) {
        Objects.requireNonNull(action);
    }

    @Override
    public void remove()
    { throw new UnsupportedOperationException("NullIterator.remove") ;}
}
