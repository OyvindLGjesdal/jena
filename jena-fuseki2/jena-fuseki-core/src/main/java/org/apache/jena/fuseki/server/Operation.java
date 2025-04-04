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

package org.apache.jena.fuseki.server;

import static org.apache.jena.atlas.lib.Lib.lowercase;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.apache.jena.atlas.logging.Log;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.irix.IRIException;
import org.apache.jena.irix.IRIx;

/**
 * Operations are symbol to look up in the {@link OperationRegistry#operationToHandler} map. The name
 * of an {@code Operation} is not related to the service name used to invoke the operation
 * which is determined by the {@link Endpoint}.
 */
public class Operation {

    /** Create/intern. Maps short name to operation. */
    static private Map<Node, Operation> mgr = new HashMap<>();

    static public Operation get(Node node) { return mgr.get(node); }

    /**
     * Create an Operation - this operation interns operations so there is only
     * one object for each operation. It is an extensible enum.
     */
    static public Operation alloc(String iriStr, String name, String description) {
        try {
            IRIx iri = IRIx.create(iriStr);
            if ( !iri.isReference() )
                Log.warn(Operation.class, "Poor Operation name: "+iriStr+" : Relative IRI");
        } catch (IRIException ex) {
            Log.error(Operation.class, "Poor Operation name: "+iriStr+" : Not an IRI");
        }
        Node node = NodeFactory.createURI(iriStr);
        return alloc(node, name, description);
    }

    /**
     * Create an Operation - this operation interns operations so there is only
     * object for each operation. It is an extensible enum.
     */
    static public Operation alloc(Node op, String name, String description) {
        return mgr.computeIfAbsent(op, (x)->create(x, name, description));
    }

    /** Create; not registered */
    static private Operation create(Node id, String shortName, String description) {
        // Currently, (3.13.0) the JS name is the short display name in lower
        // case. Just in case it diverges in the future, leave provision for
        // a different setting.
        return new Operation(id, shortName, lowercase(shortName), description);
    }

    public static final Operation Query    = alloc(FusekiVocabG.opQuery,   "query",   "SPARQL Query");
    public static final Operation Update   = alloc(FusekiVocabG.opUpdate,  "update",  "SPARQL Update");
    public static final Operation GSP_R    = alloc(FusekiVocabG.opGSP_r,   "gsp-r",   "Graph Store Protocol (Read)");
    public static final Operation GSP_RW   = alloc(FusekiVocabG.opGSP_rw,  "gsp-rw",  "Graph Store Protocol");

    public static final Operation Shacl    = alloc(FusekiVocabG.opShacl,   "SHACL",   "SHACL Validation");
    public static final Operation Upload   = alloc(FusekiVocabG.opUpload,  "upload",  "File Upload");
    public static final Operation Patch    = alloc(FusekiVocabG.opPatch,   "patch",   "RDF Patch");

    public static final Operation NoOp     = alloc(FusekiVocabG.opNoOp,    "no-op",   "No Op");

    public static final Operation PREFIXES_R   = alloc(FusekiVocabG.opPREFIXES_R,   "prefixes-r",   "Read prefixes");
    public static final Operation PREFIXES_RW  = alloc(FusekiVocabG.opPREFIXES_RW,  "prefixes-rw",  "Read-write prefixes");


    static {
        // Not everyone will remember "_" vs "-" so ...
        altName(FusekiVocabG.opNoOp_alt,   FusekiVocabG.opNoOp);
        altName(FusekiVocabG.opGSP_r_alt,  FusekiVocabG.opGSP_r);
        altName(FusekiVocabG.opGSP_rw_alt, FusekiVocabG.opGSP_rw);
    }

    // -- Object
    private final Node id;
    private final String name;
    // Name used in JSON in the "server" description and "stats" details.
    // This name is know to the JS code (e.g. dataset.js).
    private final String jsName;

    private final String description;

    private Operation(Node fullName, String name, String jsName, String description) {
        this.id = fullName;
        this.name = name;
        // Currently, this
        this.jsName = jsName;
        this.description = description;
    }

    public Node getId() {
        return id;
    }

    /** Return the display name for this operation. */
    public String getName() {
        return name;
    }

    /**
     * Name used in JSON in the "server" description and "stats" details.
     * Highlighted by JENA-1766.
     * This name is know to the JS code.
     */
    public String getJsonName() {
        return jsName;
    }

    /** Return the description for this operation. */
    public String getDescription() {
        return description;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    // Could be this == obj
    // because we intern'ed the object

    @Override
    public boolean equals(Object obj) {
        if ( this == obj )
            return true;
        if ( !(obj instanceof Operation) )
            return false;
        Operation other = (Operation)obj;
        return Objects.equals(id, other.id);
    }

    @Override
    public String toString() {
        return name;
    }

    private static void altName(Node altName, Node properName) {
        Operation op = mgr.get(properName);
        mgr.put(altName, op);
    }
}

