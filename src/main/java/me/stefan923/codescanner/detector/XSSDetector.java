package me.stefan923.codescanner.detector;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import me.stefan923.codescanner.Vulnerability;

import java.util.*;

public class XSSDetector implements VulnerabilityDetector {
    @Override
    public List<Vulnerability> detect(Node node, Map<String, Boolean> taintMap) {
        List<Vulnerability> xssVulnerabilities = new ArrayList<>();

        if (node instanceof MethodCallExpr mce) {
            String methodName = mce.getNameAsString();
            if (isVulnerableSink(methodName)) {
                for (Expression arg : mce.getArguments()) {
                    if (isTainted(arg, taintMap) && !isEscapedCall(arg)) {
                        String className = getEnclosingClassName(mce);
                        int line = mce.getBegin().map(p -> p.line).orElse(-1);
                        xssVulnerabilities.add(new Vulnerability("XSS",
                                "Method call " + methodName + " outputs tainted data",
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

            if (isEscapeMethod(callName)) {
                return false;
            }

            if (isInputSource(callName)) {
                return true;
            }
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

    private boolean isEscapedCall(Expression expr) {
        if (expr.isMethodCallExpr()) {
            return isEscapeMethod(expr.asMethodCallExpr().getNameAsString());
        }
        return false;
    }

    private boolean isEscapeMethod(String methodName) {
        return methodName.equals("escapeHtml") ||
                methodName.equals("encodeForHTML") ||
                methodName.equals("sanitize");
    }

    private boolean isInputSource(String methodName) {
        return methodName.equals("getParameter") ||
                methodName.equals("nextLine") ||
                methodName.equals("readLine") ||
                methodName.equals("getPathVariable") ||
                methodName.equals("getRequestBody") ||
                methodName.equals("getRequestParam") ||
                methodName.equals("getQueryParam") ||
                methodName.equals("getHeader") ||
                methodName.equals("getCookie");
    }

    private boolean isVulnerableSink(String methodName) {
        // Output to UI/HTTP
        if (methodName.startsWith("print") ||
                methodName.startsWith("append") ||
                methodName.startsWith("set") ||
                methodName.equals("send") ||
                methodName.equals("display")) {
            return true;
        }

        // Database operations
        if (methodName.startsWith("execute") ||
                methodName.startsWith("query") ||
                methodName.startsWith("update")) {
            return true;
        }

        // File operations
        if (methodName.startsWith("write") ||
                methodName.startsWith("save") ||
                methodName.equals("store")) {
            return true;
        }

        // Network operations
        if (methodName.startsWith("send") ||
                methodName.equals("post") ||
                methodName.equals("put")) {
            return true;
        }

        // Logging
        return methodName.startsWith("log") ||
                methodName.equals("debug") ||
                methodName.equals("info") ||
                methodName.equals("warn") ||
                methodName.equals("error");
    }

    private String getEnclosingClassName(Node node) {
        Optional<ClassOrInterfaceDeclaration> cid = node.findAncestor(ClassOrInterfaceDeclaration.class);
        return cid.map(ClassOrInterfaceDeclaration::getNameAsString).orElse("<unknown>");
    }
}
