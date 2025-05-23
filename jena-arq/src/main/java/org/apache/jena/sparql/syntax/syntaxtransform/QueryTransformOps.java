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

package org.apache.jena.sparql.syntax.syntaxtransform;

import java.util.*;

import org.apache.jena.graph.Node;
import org.apache.jena.graph.Triple;
import org.apache.jena.query.Query;
import org.apache.jena.query.QueryVisitor;
import org.apache.jena.query.SortCondition;
import org.apache.jena.rdf.model.Literal;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.shared.JenaException;
import org.apache.jena.shared.PrefixMapping;
import org.apache.jena.shared.impl.PrefixMappingImpl;
import org.apache.jena.sparql.ARQException;
import org.apache.jena.sparql.core.*;
import org.apache.jena.sparql.expr.*;
import org.apache.jena.sparql.graph.NodeTransform;
import org.apache.jena.sparql.modify.request.QuadAcc;
import org.apache.jena.sparql.syntax.*;

/** Support for transformation of query abstract syntax. */
public class QueryTransformOps {

    /**
     * Replace variables in a query by RDF terms.
     * The replacements are added to the return queries SELECT clause (if a SELECT query).
     *
     * @throws QueryScopeException if the query contains variables used in a
     *   way that does not allow substitution (.e.g {@code AS ?var} or used in
     *   {@code VALUES}).
     *
     *  @see #replaceVars(Query, Map) to replace variables without adding the replacements to the SELECT clause.
     */
    public static Query syntaxSubstitute(Query input, Map<Var, ? extends Node> substitutions) {
        Query query2 = transformSubstitute(input, substitutions);
        // Include substitutions
        if ( input.isSelectType() ) {
            query2.setQueryResultStar(false);
            List<Var> projectVars = query2.getProjectVars();
            substitutions.forEach((v, n) -> {
                if ( ! projectVars.contains(v) ) {
                    var nv = NodeValue.makeNode(n);
                    query2.getProject().update(v, NodeValue.makeNode(n));
                }
            });
        }
        return query2;
    }

    /** @deprecated Use {@link #replaceVars} */
    @Deprecated
    public static Query transform(Query query, Map<Var, ? extends Node> substitutions) {
        return replaceVars(query, substitutions);
    }

    /**
     * Transform a query based on a mapping from {@link Var} variable to replacement {@link Node}.
     * The replacement can be a constant or another variable.
     * This operation does not record the substitution made.
     *
     * See {@link #syntaxSubstitute(Query,Map)}
     * @throws QueryScopeException if the query contains variables used in a
     *   way that does not allow constant substitution.
     */
    public static Query replaceVars(Query query, Map<Var, ? extends Node> substitutions) {
        return transformSubstitute(query, substitutions);
    }

    /** @deprecated Use {@link #queryReplaceVars} */
    @Deprecated
    public static Query transformQuery(Query query, Map<String, ? extends RDFNode> substitutions)    {
        return queryReplaceVars(query, substitutions);
    }

    /**
     * Transform a query based on a mapping from variable name to replacement
     * {@link RDFNode} (a {@link Resource} (or blank node) or a {@link Literal}).
     */
    public static Query queryReplaceVars(Query query, Map<String, ? extends RDFNode> substitutions) {
        // Must have a different name because of Java's erasure of parameterised types.
        Map<Var, Node> map = TransformElementLib.convert(substitutions);
        return replaceVars(query, map);
    }

    private static Query transformSubstitute(Query query, Map<Var, ? extends Node> substitutions) {
        // Those variables that are mapped to constants, not variables.
        // Replacing a variable by another variable is always possible - no scoping issues.
        Set<Var> varsForConst = new HashSet<>();
        substitutions.forEach((var,node) -> {
          if (! ( node instanceof Var ) )
              varsForConst.add(var);
        });
        QuerySyntaxSubstituteScope.scopeCheck(query, varsForConst);

        ElementTransform eltrans = new ElementTransformSubst(substitutions);
        NodeTransform nodeTransform = new NodeTransformSubst(substitutions);
        ExprTransform exprTrans = new ExprTransformNodeElement(nodeTransform, eltrans);
        return transform(query, eltrans, exprTrans);
    }

    // ----------------

    public static Query transform(Query query, ElementTransform transform) {
        ExprTransform noop = new ExprTransformApplyElementTransform(transform);
        return transform(query, transform, noop);
    }

    /**
     * Transform a query using {@link ElementTransform} and {@link ExprTransform}.
     * It is the responsibility of these transforms to transform to a legal SPARQL query.
     */
    public static Query transform(Query query, ElementTransform transform, ExprTransform exprTransform) {
        Query q2 = QueryTransformOps.shallowCopy(query);
        // Mutate the q2 structures which are already allocated and no other code can access yet.
        mutateByQueryType(q2, exprTransform);
        mutateVarExprList(q2.getGroupBy(), exprTransform);
        mutateExprList(q2.getHavingExprs(), exprTransform);
        if (q2.getOrderBy() != null)
            mutateSortConditions(q2.getOrderBy(), exprTransform);
        mutateQueryPattern(q2, transform, exprTransform);
        // Reset internal to only what now can be seen.
        q2.resetResultVars();
        setAggregators(q2, query, exprTransform);
        return q2;
    }

    private static void mutateQueryPattern(Query q2, ElementTransform transform, ExprTransform exprTransform) {
        Element el = q2.getQueryPattern();

        // Explicit null check to prevent warning in ElementTransformer
        Element el2 = el == null ? null : ElementTransformer.transform(el, transform, exprTransform);
        // Top level is always a group or a subquery
        if (el2 != null && !(el2 instanceof ElementGroup) && !(el2 instanceof ElementSubQuery)) {
            ElementGroup eg = new ElementGroup();
            eg.addElement(el2);
            el2 = eg;
        }
        q2.setQueryPattern(el2);

        // Pass a values data block through the transform by wrapping it as an ElementData
        if(q2.hasValues()) {
            ElementData elData = new ElementData(q2.getValuesVariables(), q2.getValuesData());
            Element rawElData2 = ElementTransformer.transform(elData, transform, exprTransform);
            if(!(rawElData2 instanceof ElementData)) {
                throw new ARQException("Can't transform a values data block to a different type other than ElementData. "
                        + "Transform yeld type " + Objects.toString(rawElData2.getClass()));
            }
            ElementData elData2 = (ElementData)rawElData2;
            q2.setValuesDataBlock(elData2.getVars(), elData2.getRows());
        }
    }

    private static void setAggregators(Query newQuery, Query query, ExprTransform exprTransform) {
        for (ExprAggregator aggregator : query.getAggregators()) {
            newQuery.getAggregators().add((ExprAggregator) exprTransform.transform(aggregator));
        }
    }

    // Do the result form part of the cloned query.
    private static void mutateByQueryType(Query q2, ExprTransform exprTransform) {
        switch(q2.queryType()) {
            case ASK : break;
            case CONSTRUCT :
            //case CONSTRUCT_QUADS :
                // Variables in CONSTRUCT template.
                Template template = q2.getConstructTemplate();
                QuadAcc acc = new QuadAcc();
                List<Quad> quads = template.getQuads();
                quads.forEach(q->{
                    Node g = transformOrSame(q.getGraph(), exprTransform);
                    Node s = transformOrSame(q.getSubject(), exprTransform);
                    Node p = transformOrSame(q.getPredicate(), exprTransform);
                    Node o = transformOrSame(q.getObject(), exprTransform);
                    acc.addQuad(Quad.create(g, s, p, o));
                });
                Template template2 = new Template(acc);
                q2.setConstructTemplate(template2);
                break;
            case DESCRIBE :
                // Variables in describe.
                mutateDescribeVar(q2.getProjectVars(), q2.getResultURIs(), exprTransform);
                break;
            case SELECT :
                mutateVarExprList(q2.getProject(), exprTransform);
                break;
            case CONSTRUCT_JSON :
                Map<String, Node> newJsonMapping = transformJsonMapping(q2.getJsonMapping(), exprTransform);
                q2.setJsonMapping(newJsonMapping);
                break;
            case UNKNOWN :
            default :
                throw new JenaException("Unknown query type");
        }
    }

    // Transform CONSTRUCT query template
    private static void mutateConstruct(Query query, Query query2, ElementTransform transform) {
        if ( query.isConstructQuad() ) {
            Template template = query.getConstructTemplate();
            List<Quad> quads = template.getQuads();
            QuadAcc accQuads = new QuadAcc();
            quads.forEach(quad1->{
                Quad quad2 = transform.transform(quad1);
                accQuads.addQuad(quad2);
            });
            Template template2 = new Template(accQuads);
            query2.setConstructTemplate(template2);
            return;
        }
        if (query.isConstructType() ) {
            Template template = query.getConstructTemplate();
            List<Triple> triples = template.getBGP().getList();
            BasicPattern accTriple = new BasicPattern();
            triples.forEach(triple1->{
                Triple triple2 = transform.transform(triple1);
                accTriple.add(triple2);
            });
            Template template2 = new Template(accTriple);
            query2.setConstructTemplate(template2);
            return;
        }
    }

    // ** Mutates the List
    private static void mutateExprList(List<Expr> exprList, ExprTransform exprTransform) {
        for (int i = 0; i < exprList.size(); i++) {
            Expr e1 = exprList.get(0);
            Expr e2 = ExprTransformer.transform(exprTransform, e1);
            if (e2 == null || e2 == e1)
                continue;
            exprList.set(i, e2);
        }
    }

    private static void mutateSortConditions(List<SortCondition> conditions, ExprTransform exprTransform) {
        for (int i = 0; i < conditions.size(); i++) {
            SortCondition s1 = conditions.get(i);
            Expr e = ExprTransformer.transform(exprTransform, s1.expression);
            if (e == null || s1.expression.equals(e))
                continue;
            conditions.set(i, new SortCondition(e, s1.direction));
        }
    }

    private static void mutateVarExprList(VarExprList varExprList, ExprTransform exprTransform) {
        VarExprList x = transformVarExprList(varExprList, exprTransform);
        varExprList.clear();
        varExprList.addAll(x);
    }

    private static void mutateDescribeVar(List<Var> varList, List<Node> constants, ExprTransform exprTransform) {
        List<Var> varList2 = new ArrayList<>(varList.size());
        for (Var v : varList) {
            Node n = transformOrSame(v, exprTransform);
            if ( n != v ) {
                if ( !constants.contains(n) )
                    constants.add(n);
                continue;
            }
            varList2.add(v);
        }
        if ( varList2.size() != varList.size() ) {
            varList.clear();
            varList.addAll(varList2);
        }
    }

    private static VarExprList transformVarExprList(VarExprList varExprList, ExprTransform exprTransform) {
        VarExprList varExprList2 = new VarExprList();
        boolean changed = false;

        for (Var v : varExprList.getVars()) {
            Expr e = varExprList.getExpr(v);
            // Transform variable.
            ExprVar ev = new ExprVar(v);
            Expr ev2 = exprTransform.transform(ev);
            if (ev != ev2)
                changed = true;

            if ( e == null ) {
                // Variable only.
                if ( ev2.isConstant() ) {
                    // Skip or old var, assign so it become (?old AS substitute)
                    // Skip .
                    // Require transform to add back substitutions "for the record";
                    varExprList2.remove(v);
                    varExprList2.add(v, ev2);
                }
                else if ( ev2.isVariable() ) {
                    varExprList2.add(ev2.asVar());
                } else {
                    throw new ARQException("Can't substitute " + v + " because it's not a simple value: " + ev2);
                }
                continue;
            }

            // There was an expression.
            Expr e2 = ExprTransformer.transform(exprTransform, e);
            if ( e2 != e )
                changed = true;
            if ( ! ev2.isVariable() )
                throw new ARQException("Can't substitute ("+v+", "+e+") as ("+ev2+", "+e2+")");
            varExprList2.add(ev.asVar(), e2);

        }
        return varExprList2;
    }

    private static Map<String, Node> transformJsonMapping(Map<String, Node> jsonMapping, ExprTransform exprTransform) {
        Map<String, Node> result = new LinkedHashMap<>();
        jsonMapping.forEach((k,n)->{
            Node n2 = transformOrSame(n, exprTransform);
            result.put(k, n2);
        });
        return result;
    }

    // Transform a variable node.
    // Returns the argument java object for "no transform"
    private static Node transformOrSame(Node node, ExprTransform exprTransform) {
        if ( ! Var.isVar(node) )
            return node;
        Expr e2 = exprTransform.transform(node);
        if ( e2 == null )
            return node;
        if ( ! e2.isConstant() )
            return node;
        return e2.getConstant().getNode();
    }

    static class QueryShallowCopy implements QueryVisitor {
        final Query newQuery = new Query();

        QueryShallowCopy() {}

        @Override
        public void startVisit(Query query) {
            newQuery.setSyntax(query.getSyntax());

            if (query.explicitlySetBaseURI())
                newQuery.setBaseURI(query.getPrologue().getBaseURI());

            newQuery.setQueryResultStar(query.isQueryResultStar());

            if (query.hasDatasetDescription()) {
                DatasetDescription desc = query.getDatasetDescription();
                for (String x : desc.getDefaultGraphURIs())
                    newQuery.addGraphURI(x);
                for (String x : desc.getNamedGraphURIs())
                    newQuery.addNamedGraphURI(x);
            }
        }

        @Override
        public void visitPrologue(Prologue prologue) {
            // newQuery.setBaseURI(prologue.getResolver());
            PrefixMapping pmap = new PrefixMappingImpl().setNsPrefixes(prologue.getPrefixMapping());
            newQuery.setPrefixMapping(pmap);
        }

        @Override
        public void visitResultForm(Query q) {
        }

        @Override
        public void visitSelectResultForm(Query query) {
            newQuery.setQuerySelectType();
            newQuery.setDistinct(query.isDistinct());
            newQuery.setReduced(query.isReduced());
            copyProjection(query);
        }

        @Override
        public void visitConstructResultForm(Query query) {
            newQuery.setQueryConstructType();
            newQuery.setConstructTemplate(query.getConstructTemplate());
        }

        @Override
        public void visitDescribeResultForm(Query query) {
            newQuery.setQueryDescribeType();
            for (Node x : query.getResultURIs())
                newQuery.addDescribeNode(x);
            copyProjection(query);
        }

        @Override
        public void visitAskResultForm(Query query) {
            newQuery.setQueryAskType();
        }

        @Override
        public void visitJsonResultForm(Query query) {
            newQuery.setQueryJsonType();
            newQuery.setJsonMapping(query.getJsonMapping());
        }

        @Override
        public void visitDatasetDecl(Query query) {
        }

        @Override
        public void visitQueryPattern(Query query) {
            newQuery.setQueryPattern(query.getQueryPattern());
        }

        @Override
        public void visitGroupBy(Query query) {
            if (query.hasGroupBy()) {
                VarExprList x = query.getGroupBy();

                for (Var v : x.getVars()) {
                    Expr expr = x.getExpr(v);
                    if (expr == null)
                        newQuery.addGroupBy(v);
                    else
                        newQuery.addGroupBy(v, expr);
                }
            }
        }

        @Override
        public void visitHaving(Query query) {
            if (query.hasHaving()) {
                for (Expr expr : query.getHavingExprs())
                    newQuery.addHavingCondition(expr);
            }
        }

        @Override
        public void visitOrderBy(Query query) {
            if (query.hasOrderBy()) {
                for (SortCondition sc : query.getOrderBy())
                    newQuery.addOrderBy(sc);
            }
        }

        @Override
        public void visitLimit(Query query) {
            newQuery.setLimit(query.getLimit());
        }

        @Override
        public void visitOffset(Query query) {
            newQuery.setOffset(query.getOffset());
        }

        @Override
        public void visitValues(Query query) {
            if (query.hasValues())
                newQuery.setValuesDataBlock(query.getValuesVariables(), query.getValuesData());
        }

        @Override
        public void finishVisit(Query query) {
        }

        // In some (legacy?) cases, describe queries make use of projection instead
        // of result nodes
        public void copyProjection(Query query) {
            VarExprList x = query.getProject();
            for (Var v : x.getVars()) {
                Expr expr = x.getExpr(v);
                if (expr == null)
                    newQuery.addResultVar(v);
                else
                    newQuery.addResultVar(v, expr);
            }
        }
    }

    public static Query shallowCopy(Query query) {
        QueryShallowCopy copy = new QueryShallowCopy();
        query.visit(copy);
        Query q2 = copy.newQuery;
        return q2;
    }
}
