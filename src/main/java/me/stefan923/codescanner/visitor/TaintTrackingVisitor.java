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
            Boolean taintStatus = checkExpressionTaintStatus(init, taintMap);
            if (taintStatus != null) {
                taintMap.put(var.getNameAsString(), taintStatus);
            }
        }
    }

    @Override
    public void visit(AssignExpr assign, Map<String, Boolean> taintMap) {
        super.visit(assign, taintMap);
        if (assign.getTarget().isNameExpr()) {
            String varName = assign.getTarget().asNameExpr().getNameAsString();
            Boolean taintStatus = checkExpressionTaintStatus(assign.getValue(), taintMap);
            if (taintStatus != null) {
                taintMap.put(varName, taintStatus);
            }
        }
    }

    private Boolean checkExpressionTaintStatus(Expression expr, Map<String, Boolean> taintMap) {
        if (isEscaped(expr)) {
            return false;
        }

        if (isTainted(expr, taintMap)) {
            return true;
        }

        if (expr.isNameExpr()) {
            return taintMap.get(expr.asNameExpr().getNameAsString());
        }

        return null;
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

    private boolean isEscaped(Expression expr) {
        if (expr.isMethodCallExpr()) {
            String methodName = expr.asMethodCallExpr().getNameAsString();
            return methodName.equals("escapeHtml") ||
                    methodName.equals("encodeForHTML") ||
                    methodName.equals("sanitize");
        }
        return false;
    }
}
