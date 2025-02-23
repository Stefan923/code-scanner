package me.stefan923.codescanner.detector;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import me.stefan923.codescanner.Vulnerability;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class XSSDetector implements VulnerabilityDetector {
    @Override
    public List<Vulnerability> detect(Node node, Map<String, Boolean> taintMap) {
        List<Vulnerability> xssVulnerabilities = new ArrayList<>();

        if (node instanceof MethodCallExpr mce) {
            String methodName = mce.getNameAsString();
            if (methodName.startsWith("print") || methodName.startsWith("write")) {
                for (Expression arg : mce.getArguments()) {
                    if (isTainted(arg, taintMap)) {
                        String className = getEnclosingClassName(mce);
                        int line = mce.getBegin().map(p -> p.line).orElse(-1);
                        xssVulnerabilities.add(new Vulnerability("XSS",
                                "Method call " + methodName + " outputs tainted data.",
                                className, line));
                    }
                }
            }
        }

        return xssVulnerabilities;
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

    private String getEnclosingClassName(Node node) {
        Optional<ClassOrInterfaceDeclaration> cid = node.findAncestor(ClassOrInterfaceDeclaration.class);
        return cid.map(ClassOrInterfaceDeclaration::getNameAsString).orElse("<unknown>");
    }
}
