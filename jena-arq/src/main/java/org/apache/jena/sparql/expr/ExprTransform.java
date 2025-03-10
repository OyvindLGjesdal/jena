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

package org.apache.jena.sparql.expr;

import org.apache.jena.graph.Node;
import org.apache.jena.sparql.algebra.Op ;
import org.apache.jena.sparql.core.Var;

public interface ExprTransform
{
    public Expr transform(ExprFunction0 func) ;
    public Expr transform(ExprFunction1 func, Expr expr1) ;
    public Expr transform(ExprFunction2 func, Expr expr1, Expr expr2) ;
    public Expr transform(ExprFunction3 func, Expr expr1, Expr expr2, Expr expr3) ;
    public Expr transform(ExprFunctionN func, ExprList args) ;
    public Expr transform(ExprFunctionOp funcOp, ExprList args, Op opArg) ;
    public Expr transform(NodeValue nv) ;

    public default Expr transform(Node node) {
        if ( Var.isVar(node) ) {
            ExprVar exprVar = new ExprVar(node);
            return transform(exprVar);
        }
        NodeValue nv = NodeValue.makeNode(node);
        return transform(nv);
    }

    public Expr transform(ExprNone exprNone) ;
    public Expr transform(ExprVar exprVar) ;
    public Expr transform(ExprAggregator eAgg) ;
}
