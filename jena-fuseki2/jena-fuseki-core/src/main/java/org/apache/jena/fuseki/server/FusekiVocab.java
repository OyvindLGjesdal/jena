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

import org.apache.jena.fuseki.FusekiException;
import org.apache.jena.irix.IRIException;
import org.apache.jena.irix.IRIx;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.ResourceFactory;

public class FusekiVocab
{
    // Keep in-step with FusekiVocabG (same constants, but as nodes).
    public static final String NS = "http://jena.apache.org/fuseki#";

    public static final Resource tServer            = resource("Server");

    public static final Resource fusekiService      = resource("Service");

    public static final Property pServices          = property("services");

    // Server endpoints.
    public static final Property pServerPing        = property("pingEP");
    public static final Property pServerStats       = property("statsEP");
    public static final Property pServerMetrics     = property("metricsEP");
    public static final Property pServerCompact     = property("compactEP");

    // Server features
    // Fuseki main - servlet context.
    public static final Property pServerContextPath = property("contextPath");

    // Endpoint description.
    public static final Property pServiceName               = property("name");
    public static final Property pEndpointName              = property("name");
    public static final Property pPasswordFile              = property("passwd");
    public static final Property pRealm                     = property("realm");
    public static final Property pAuth                      = property("auth");
    public static final Property pEndpoint                  = property("endpoint");
    public static final Property pOperation                 = property("operation");
    public static final Property pAllowedUsers              = property("allowedUsers");
    public static final Property pTimeout                   = property("timeout");
    public static final Property pImplementation            = property("implementation");
    public static final Property pQueryLimit                = property("queryLimit");
    public static final Property pUnionDefaultGraph         = property("unionDefaultGraph");
    public static final Property pAllowTimeoutOverride      = property("allowTimeoutOverride");
    public static final Property pMaximumTimeoutOverride    = property("maximumTimeoutOverride");
    public static final Property pDataset                   = property("dataset");

    // Endpoint description - old style.
    public static final Property pServiceQueryEP                = property("serviceQuery");
    public static final Property pServiceUpdateEP               = property("serviceUpdate");
    public static final Property pServiceUploadEP               = property("serviceUpload");
    public static final Property pServiceShaclEP                = property("serviceShacl");
    public static final Property pServiceReadWriteGraphStoreEP  = property("serviceReadWriteGraphStore");
    public static final Property pServiceReadGraphStoreEP       = property("serviceReadGraphStore");
    // No longer used.
//    public static final Property pServiceReadWriteQuadsEP       = property("serviceReadWriteQuads");
//    public static final Property pServiceReadQuadsEP            = property("serviceReadQuads");

    // Operation names : the standard operations.
    // "alt" names are the same but using "_" not "_".
    public static final Resource opQuery       = resource("query");
    public static final Resource opUpdate      = resource("update");
    public static final Resource opUpload      = resource("upload");
    public static final Resource opGSP_r       = resource("gsp-r");
    public static final Resource opGSP_r_alt   = resource("gsp_r");
    public static final Resource opGSP_rw      = resource("gsp-rw");
    public static final Resource opGSP_rw_alt  = resource("gsp_rw");
    public static final Resource opNoOp        = resource("no-op");
    public static final Resource opNoOp_alt    = resource("no_op");
    public static final Resource opShacl       = resource("shacl");
    public static final Resource opPatch       = resource("patch");

    public static final Resource opPREFIXES_R       = resource("prefixes-r");
    public static final Resource opPREFIXES_RW      = resource("prefixes-rw");

    private static Resource resource(String localname) { return ResourceFactory.createResource(iri(localname)); }
    private static Property property(String localname) { return ResourceFactory.createProperty(iri(localname)); }

    private static String iri(String localname) {
        String uri = NS + localname;
        try {
            IRIx iri = IRIx.create(uri);
            if ( ! iri.isReference() )
                throw new FusekiException("Bad IRI (relative): "+uri);
            return uri;
        } catch (IRIException ex) {
            throw new FusekiException("Bad IRI: "+uri);
        }
    }
}

