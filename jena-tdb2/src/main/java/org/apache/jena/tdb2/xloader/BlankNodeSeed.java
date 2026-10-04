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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import org.apache.jena.riot.lang.LabelToNode;
import org.apache.jena.tdb2.TDBException;

/**
 * One seed for the blank node labels of a load, so the node table and ingest steps,
 * which parse the input separately (in separate JVMs), make the same blank node for a
 * label. Otherwise each parse has its own random seed: the node table step's entries for
 * blank nodes are never found again, and ingest allocates every blank node a second time.
 * <p>
 * The node table step creates the seed and writes it to the temporary directory; ingest
 * reads it. Each input file has its own seed derived from the load's seed and the file's
 * position in the list of input files, so equal labels in different files are different
 * blank nodes, as with separate parses.
 */
final class BlankNodeSeed {
    private BlankNodeSeed() {}

    /** Create and record a new seed for a load. */
    static UUID create(XLoaderFiles files) {
        UUID seed = UUID.randomUUID();
        try {
            Files.writeString(Path.of(files.blankNodeSeed), seed + "\n", StandardCharsets.US_ASCII);
        } catch (IOException ex) {
            throw new TDBException("Failed to write the blank node seed: " + files.blankNodeSeed, ex);
        }
        return seed;
    }

    /** The load's seed written by the node table step, or null if there is none. */
    static UUID read(XLoaderFiles files) {
        Path path = Path.of(files.blankNodeSeed);
        if ( !Files.isRegularFile(path) )
            return null;
        try {
            return UUID.fromString(Files.readString(path, StandardCharsets.US_ASCII).strip());
        } catch (IOException | IllegalArgumentException ex) {
            throw new TDBException("Failed to read the blank node seed: " + files.blankNodeSeed, ex);
        }
    }

    /** The seed for the input file at {@code fileIndex} (0-based) of a load. */
    static UUID fileSeed(UUID loadSeed, int fileIndex) {
        return UUID.nameUUIDFromBytes((loadSeed + "/" + fileIndex).getBytes(StandardCharsets.US_ASCII));
    }

    /** A new label policy for one parse of the input file at {@code fileIndex}. */
    static LabelToNode labelToNode(UUID loadSeed, int fileIndex) {
        return LabelToNode.createScopeByDocumentHash(fileSeed(loadSeed, fileIndex));
    }
}
