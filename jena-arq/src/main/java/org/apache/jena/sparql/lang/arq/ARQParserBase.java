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

package org.apache.jena.sparql.lang.arq;
import java.util.Map;

import org.apache.jena.atlas.json.io.JSONHandler ;
import org.apache.jena.atlas.json.io.JSONHandlerBase ;
import org.apache.jena.atlas.lib.NotImplemented ;
import org.apache.jena.cdt.CompositeDatatypeList;
import org.apache.jena.cdt.CompositeDatatypeMap;
import org.apache.jena.datatypes.DatatypeFormatException;
import org.apache.jena.datatypes.RDFDatatype;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.riot.system.ParserProfile;
import org.apache.jena.riot.system.RiotLib;
import org.apache.jena.sparql.core.BasicPattern;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.sparql.lang.SPARQLParserBase ;
import org.apache.jena.sparql.syntax.Element;
import org.apache.jena.sparql.syntax.ElementGroup;
import org.apache.jena.sparql.syntax.ElementNamedGraph;
import org.apache.jena.sparql.syntax.ElementPathBlock;
import org.apache.jena.sparql.syntax.Template;

public class ARQParserBase extends SPARQLParserBase
{
    // JSON
    JSONHandler handler = new JSONHandlerBase() ;

    public void setHandler(JSONHandler handler)
    {
        if ( handler == null )
            this.handler = new JSONHandlerBase() ;
        else
            this.handler = handler ;
    }

    // All the signals from the parsing process.
    protected void jsonStartParse(long currLine, long currCol)                 { handler.startParse(currLine, currCol) ; }
    protected void jsonFinishParse(long currLine, long currCol)                { handler.finishParse(currLine, currCol) ; }

    protected void jsonStartObject(long currLine, long currCol)                { handler.startObject(currLine, currCol) ; }
    protected void jsonFinishObject(long currLine, long currCol)               { handler.finishObject(currLine, currCol) ; }

    protected void jsonStartPair(long currLine, long currCol)                  { handler.startPair(currLine, currCol) ; }
    protected void jsonKeyPair(long currLine, long currCol)                    { handler.keyPair(currLine, currCol) ; }
    protected void jsonFinishPair(long currLine, long currCol)                 { handler.finishPair(currLine, currCol) ; }

    protected void jsonStartArray(long currLine, long currCol)                 { handler.startArray(currLine, currCol) ; }
    protected void jsonElement(long currLine, long currCol)                    { handler.element(currLine, currCol) ; }
    protected void jsonFinishArray(long currLine, long currCol)                { handler.finishArray(currLine, currCol) ; }

    protected void jsonValueString(String image, long currLine, long currCol)
    {
        // Strip quotes
        image = image.substring(1,image.length()-1) ;
        handler.valueString(image, currLine, currCol) ;
    }

    protected void jsonValueKeyString(String image, long currLine, long currCol) { handler.valueString(image, currLine, currCol) ; }
    protected void jsonValueInteger(String image, long currLine, long currCol)   { handler.valueInteger(image, currLine, currCol) ; }
    protected void jsonValueDecimal(String image, long currLine, long currCol)   { handler.valueDecimal(image, currLine, currCol) ; }
    protected void jsonValueDouble(String image, long currLine, long currCol)    { handler.valueDouble(image, currLine, currCol) ; }
    protected void jsonValueBoolean(boolean b, long currLine, long currCol)      { handler.valueBoolean(b, currLine, currCol) ; }
    protected void jsonValueNull(long currLine, long currCol)                    { handler.valueNull(currLine, currCol) ; }

    protected void jsonValueVar(String image, long currLine, long currCol)       { throw new NotImplemented("yet") ; }
    protected ElementGroup createQueryPattern(Template t){
        ElementGroup elg = new ElementGroup();
        Map<Node, BasicPattern> graphs = t.getGraphPattern();
        for(Node n: graphs.keySet()){
          Element el = new ElementPathBlock(graphs.get(n));
          if(! Quad.defaultGraphNodeGenerated.equals(n) ){
        	ElementGroup e = new ElementGroup();
        	e.addElement(el);
            el = new ElementNamedGraph(n, e);
          }
          elg.addElement(el);
        }
        return elg;
    }

    // CDT literals
    protected ParserProfile parserProfileForCDTs = null;

    @Override
    protected Node createLiteralDT(String lexicalForm, String datatypeURI, int line, int column) {
        // CDT literals need to be handled in a special way because their
        // lexical forms may contain blank node identifiers, and the same
        // blank node identifier in different CDT literals within the same
        // query must be mapped to the same blank node. To this end, we are
        // reusing the same ParserProfile for parsing all the CDT literals.
        final RDFDatatype cdtDatatype;
        if ( CompositeDatatypeList.uri.equals(datatypeURI) )
            cdtDatatype = CompositeDatatypeList.type;
        else if ( CompositeDatatypeMap.uri.equals(datatypeURI) )
            cdtDatatype = CompositeDatatypeMap.type;
        else
            cdtDatatype = null;

        if ( cdtDatatype != null ) {
            ensureParserProfileForCDTs();
            try {
                return parserProfileForCDTs.createTypedLiteral(lexicalForm, cdtDatatype, line, column);
            }
            catch ( DatatypeFormatException ex ) {
                return createIllformedLiteral(lexicalForm, cdtDatatype);
            }
        }

        return super.createLiteralDT(lexicalForm, datatypeURI, line, column);
    }

    protected void ensureParserProfileForCDTs() {
        if ( parserProfileForCDTs == null ) {
            parserProfileForCDTs = RiotLib.dftProfile();
        }
    }

    protected Node createIllformedLiteral(String lexicalForm, RDFDatatype cdtDatatype) {
        // Attention: This implementation is inefficient because, internally,
        // the following function checks whether the given lexical form is
        // well formed but, in the current case, we already know that it is
        // not well formed.
        @SuppressWarnings("deprecation")
        Node n = NodeFactory.createLiteral(lexicalForm, cdtDatatype);
        return n;
    }
}
