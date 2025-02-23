package me.stefan923.codescanner.detector;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import me.stefan923.codescanner.Vulnerability;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class CSRFDetector implements VulnerabilityDetector {
    @Override
    public List<Vulnerability> detect(Node node, Map<String, Boolean> taintMap) {
        List<Vulnerability> csrfVulnerabilities = new ArrayList<>();
        if (node instanceof MethodDeclaration md) {
            boolean isHttpHandler = md.getNameAsString().equals("doGet") || md.getNameAsString().equals("doPost");
            boolean sendsHttpRequest = md.getBody().isPresent() && bodyContainsHttpClientRequest(md.getBody().get());
            if ((isHttpHandler || sendsHttpRequest) && md.getBody().isPresent() && !bodyContainsCSRFValidation(md.getBody().get())) {
                String className = getEnclosingClassName(md);
                int line = md.getBegin().map(p -> p.line).orElse(-1);
                csrfVulnerabilities.add(new Vulnerability("CSRF",
                        "Method " + md.getNameAsString() + " does not perform CSRF validation.",
                        className, line));
            }
        }
        return csrfVulnerabilities;
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
