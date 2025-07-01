package me.stefan923.codescanner.detector;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import me.stefan923.codescanner.Vulnerability;

import java.util.*;

public class SQLiDetector implements VulnerabilityDetector {
    private static final Set<String> SQL_EXECUTION_METHODS = Set.of(
            "executeQuery", "executeUpdate", "execute", "executeLargeUpdate", "executeBatch"
    );

    private static final Set<String> SQL_PREPARATION_METHODS = Set.of(
            "prepareStatement", "prepareCall"
    );

    private static final Set<String> UNSAFE_CONCAT_METHODS = Set.of(
            "getParameter", "nextLine", "readLine", "getQueryString", "getHeader"
    );

    @Override
    public List<Vulnerability> detect(Node node, Map<String, Boolean> taintMap) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (node instanceof MethodCallExpr mce) {
            String methodName = mce.getNameAsString();
            String receiverType = resolveReceiverType(mce);

            // Check SQL execution methods with tainted arguments
            if (SQL_EXECUTION_METHODS.contains(methodName) && !mce.getArguments().isEmpty()) {
                detectTaintedArguments(mce, taintMap, vulnerabilities, "SQL execution");
            }

            // Check SQL preparation methods
            if (SQL_PREPARATION_METHODS.contains(methodName) && !mce.getArguments().isEmpty()) {
                detectTaintedArguments(mce, taintMap, vulnerabilities, "SQL preparation");
            }

            // Detect unsafe concatenation patterns
            detectUnsafeConcatenation(mce, taintMap, vulnerabilities);
        }

        // Detect inline SQL string concatenation
        if (node instanceof BinaryExpr binExpr && binExpr.getOperator() == BinaryExpr.Operator.PLUS) {
            detectInlineSqlConcat(binExpr, taintMap, vulnerabilities);
        }

        return vulnerabilities;
    }

    private void detectTaintedArguments(MethodCallExpr mce, Map<String, Boolean> taintMap,
                                        List<Vulnerability> vulnerabilities, String context) {
        for (Expression arg : mce.getArguments()) {
            if (isTainted(arg, taintMap)) {
                vulnerabilities.add(createVulnerability(mce,
                        "Tainted data used in " + context + ": " + mce.getNameAsString()));
            }
        }
    }

    private void detectUnsafeConcatenation(MethodCallExpr mce, Map<String, Boolean> taintMap,
                                           List<Vulnerability> vulnerabilities) {
        // Check for string concatenation in SQL methods
        if (mce.getNameAsString().equals("append") &&
                mce.getScope().isPresent() &&
                mce.getScope().get().toString().contains("StringBuilder")) {

            for (Expression arg : mce.getArguments()) {
                if (isTainted(arg, taintMap)) {
                    vulnerabilities.add(createVulnerability(mce,
                            "Unsafe SQL concatenation via StringBuilder.append()"));
                }
            }
        }
    }

    private void detectInlineSqlConcat(BinaryExpr binExpr, Map<String, Boolean> taintMap,
                                       List<Vulnerability> vulnerabilities) {
        if (isSqlStringContext(binExpr) &&
                (isTainted(binExpr.getLeft(), taintMap) || isTainted(binExpr.getRight(), taintMap))) {
            vulnerabilities.add(createVulnerability(binExpr,
                    "Inline SQL string concatenation with tainted data"));
        }
    }

    private boolean isSqlStringContext(Expression expr) {
        // Check if expression is part of SQL-related method call
        return expr.findAncestor(MethodCallExpr.class)
                .filter(mce -> SQL_EXECUTION_METHODS.contains(mce.getNameAsString()) ||
                        SQL_PREPARATION_METHODS.contains(mce.getNameAsString()))
                .isPresent();
    }

    private Vulnerability createVulnerability(Node node, String description) {
        return new Vulnerability("SQL Injection", description,
                getEnclosingClassName(node), node.getBegin().map(p -> p.line).orElse(-1));
    }

    private boolean isTainted(Expression expr, Map<String, Boolean> taintMap) {
        // Base case: Literal expressions are safe
        if (expr.isLiteralExpr()) return false;

        // Method calls from unsafe sources
        if (expr.isMethodCallExpr()) {
            String callName = expr.asMethodCallExpr().getNameAsString();
            if (UNSAFE_CONCAT_METHODS.contains(callName)) return true;

            // Recursively check arguments
            return expr.asMethodCallExpr().getArguments().stream()
                    .anyMatch(arg -> isTainted(arg, taintMap));
        }

        // Variable references
        if (expr.isNameExpr()) {
            String varName = expr.asNameExpr().getNameAsString();
            return taintMap.getOrDefault(varName, false);
        }

        // Binary expressions (string concatenation)
        if (expr.isBinaryExpr()) {
            BinaryExpr bin = expr.asBinaryExpr();
            if (bin.getOperator() == BinaryExpr.Operator.PLUS) {
                return isTainted(bin.getLeft(), taintMap) ||
                        isTainted(bin.getRight(), taintMap);
            }
        }

        // Field access (this.field)
        if (expr.isFieldAccessExpr()) {
            return isTainted(expr.asFieldAccessExpr().getScope(), taintMap);
        }

        // Object creation (new String(...))
        if (expr.isObjectCreationExpr()) {
            return expr.asObjectCreationExpr().getArguments().stream()
                    .anyMatch(arg -> isTainted(arg, taintMap));
        }

        return false;
    }

    private String resolveReceiverType(MethodCallExpr mce) {
        try {
            return mce.resolve().getQualifiedSignature().split("::")[0];
        } catch (Exception e) {
            return "Unknown";
        }
    }

    private String getEnclosingClassName(Node node) {
        return node.findAncestor(ClassOrInterfaceDeclaration.class)
                .map(ClassOrInterfaceDeclaration::getNameAsString)
                .orElse("<unknown>");
    }
}
