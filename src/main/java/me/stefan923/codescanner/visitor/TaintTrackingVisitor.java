package me.stefan923.codescanner.visitor;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.Map;

/**
 * Visitor that tracks "taint" for variables within a method.
 * A variable is considered tainted if its initializer (or assignment)
 * comes from user input (e.g., getParameter, nextLine, readLine) or a concatenation
 * that includes such input.
 */
public class TaintTrackingVisitor extends VoidVisitorAdapter<Map<String, Boolean>> {
    @Override
    public void visit(VariableDeclarator var, Map<String, Boolean> taintMap) {
        super.visit(var, taintMap);
        if (var.getInitializer().isPresent()) {
            Expression init = var.getInitializer().get();
            if (isTainted(init, taintMap)) {
                taintMap.put(var.getNameAsString(), true);
            }
        }
    }

    @Override
    public void visit(AssignExpr assign, Map<String, Boolean> taintMap) {
        super.visit(assign, taintMap);
        if (assign.getTarget().isNameExpr()) {
            String varName = assign.getTarget().asNameExpr().getNameAsString();
            if (isTainted(assign.getValue(), taintMap)) {
                taintMap.put(varName, true);
            }
        }
    }

    private boolean isTainted(Expression expr, Map<String, Boolean> taintMap) {
        if (expr.isMethodCallExpr()) {
            String callName = expr.asMethodCallExpr().getNameAsString();
            if (callName.equals("getParameter") || callName.equals("nextLine") || callName.equals("readLine"))
                return true;
        }
        if (expr.isNameExpr()) {
            return taintMap.getOrDefault(expr.asNameExpr().getNameAsString(), false);
        }
        if (expr.isBinaryExpr()) {
            BinaryExpr bin = expr.asBinaryExpr();
            if (bin.getOperator() == BinaryExpr.Operator.PLUS) {
                return isTainted(bin.getLeft(), taintMap) || isTainted(bin.getRight(), taintMap);
            }
        }
        for (Node child : expr.getChildNodes()) {
            if (child instanceof Expression && isTainted((Expression) child, taintMap))
                return true;
        }
        return false;
    }
}
