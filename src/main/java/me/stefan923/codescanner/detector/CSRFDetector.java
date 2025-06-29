package me.stefan923.codescanner.detector;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import me.stefan923.codescanner.Vulnerability;

import java.util.*;
import java.util.stream.Collectors;

public class CSRFDetector implements VulnerabilityDetector {
    private static final Set<String> STATE_CHANGING_METHODS = Set.of(
            "doPost", "doPut", "doDelete", "doPatch"
    );
    private static final Set<String> CSRF_VALIDATION_METHODS = Set.of(
            "validateCsrfToken", "checkCsrfToken", "verifyCsrf", "validateRequestToken"
    );
    private static final Set<String> HTTP_REQUEST_METHODS = Set.of(
            "getParameter", "getHeader", "getAttribute", "getSession"
    );

    @Override
    public List<Vulnerability> detect(Node node, Map<String, Boolean> taintMap) {
        List<Vulnerability> csrfVulnerabilities = new ArrayList<>();

        if (node instanceof MethodDeclaration md) {
            String methodName = md.getNameAsString();
            boolean isStateChanging = STATE_CHANGING_METHODS.contains(methodName);
            boolean isHttpHandler = methodName.startsWith("do") || methodName.equals("service");

            if ((isStateChanging || isHttpHandler) &&
                    md.getBody().isPresent() &&
                    !hasCSRFValidation(md.getBody().get())) {

                String className = getEnclosingClassName(md);
                int line = md.getBegin().map(p -> p.line).orElse(-1);
                csrfVulnerabilities.add(new Vulnerability("CSRF",
                        "State-changing method " + methodName + " lacks CSRF protection",
                        className, line));
            }
        }
        return csrfVulnerabilities;
    }

    private boolean hasCSRFValidation(BlockStmt body) {
        // Check for explicit validation methods
        if (body.findAll(MethodCallExpr.class).stream()
                .anyMatch(mce -> CSRF_VALIDATION_METHODS.contains(mce.getNameAsString()))) {
            return true;
        }

        // Check for token validation pattern
        List<MethodCallExpr> requestCalls = body.findAll(MethodCallExpr.class).stream()
                .filter(mce -> HTTP_REQUEST_METHODS.contains(mce.getNameAsString()))
                .collect(Collectors.toList());

        boolean hasTokenFetch = requestCalls.stream()
                .anyMatch(mce -> mce.toString().matches(".*(token|csrf).*"));

        boolean hasSessionCheck = requestCalls.stream()
                .anyMatch(mce -> mce.toString().contains("getSession"));

        boolean hasConditionalCheck = body.findAll(IfStmt.class).stream()
                .anyMatch(ifStmt -> ifStmt.getCondition().toString().matches(".*(token|csrf).*"));

        return hasTokenFetch && hasSessionCheck && hasConditionalCheck;
    }

    private boolean bodyContainsHttpClientRequest(BlockStmt body) {
        return body.findAll(MethodCallExpr.class).stream().anyMatch(mce -> {
            boolean hasHttpClient = mce.getScope().map(scope -> scope.toString().contains("HttpClient")).orElse(false);
            boolean isExecute = mce.getNameAsString().equals("execute");
            return hasHttpClient || isExecute;
        });
    }

    private boolean bodyContainsCSRFValidation(BlockStmt body) {
        return body.toString().contains("validateToken");
    }

    private String getEnclosingClassName(Node node) {
        Optional<ClassOrInterfaceDeclaration> cid = node.findAncestor(ClassOrInterfaceDeclaration.class);
        return cid.map(ClassOrInterfaceDeclaration::getNameAsString).orElse("<unknown>");
    }
}
