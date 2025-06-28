package me.stefan923.codescanner.visitor;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import me.stefan923.codescanner.Vulnerability;
import me.stefan923.codescanner.detector.VulnerabilityDetector;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DetectionVisitor extends VoidVisitorAdapter<Void> {
    private final Map<String, Boolean> taintMap;
    private final VulnerabilityDetector compositeDetector;
    private final List<Vulnerability> vulnerabilities;
    private final MethodTaintAnalyzer methodTaintAnalyzer;

    public DetectionVisitor(Map<String, Boolean> taintMap, VulnerabilityDetector compositeDetector,
                            List<Vulnerability> vulnerabilities, MethodTaintAnalyzer methodTaintAnalyzer) {
        this.taintMap = taintMap;
        this.compositeDetector = compositeDetector;
        this.vulnerabilities = vulnerabilities;
        this.methodTaintAnalyzer = methodTaintAnalyzer;
    }

    @Override
    public void visit(MethodCallExpr mce, Void arg) {
        super.visit(mce, arg);
        vulnerabilities.addAll(compositeDetector.detect(mce, taintMap));

        if (isExternalLibraryCall(mce)) {
            return;
        }

        // Propagate taint to called method if available
        mce.resolve().toAst().ifPresent(methodDecl -> {
            if (methodDecl instanceof MethodDeclaration calledMd) {
                Map<String, Boolean> calledTaint = methodTaintAnalyzer.analyzeMethod(calledMd);
                // Map arguments' taint status to parameters
                List<Expression> args = mce.getArguments();
                List<String> params = calledMd.getParameters().stream()
                        .map(p -> p.getNameAsString()).toList();
                Map<String, Boolean> paramTaint = new HashMap<>();
                for (int i = 0; i < Math.min(args.size(), params.size()); i++) {
                    Boolean tainted = isTainted(args.get(i));
                    paramTaint.put(params.get(i), tainted != null ? tainted : false);
                }
                // Recursively visit called method with propagated taint
                calledMd.getBody().ifPresent(body -> {
                    body.accept(new DetectionVisitor(paramTaint, compositeDetector, vulnerabilities, methodTaintAnalyzer), null);
                });
            }
        });
    }

    @Override
    public void visit(MethodDeclaration md, Void arg) {
        super.visit(md, arg);
        vulnerabilities.addAll(compositeDetector.detect(md, taintMap));
    }

    @Override
    public void visit(BinaryExpr binExpr, Void arg) {
        super.visit(binExpr, arg);
        vulnerabilities.addAll(compositeDetector.detect(binExpr, taintMap));
    }

    private boolean isExternalLibraryCall(MethodCallExpr mce) {
        try {
            mce.resolve().getPackageName();
            return false;
        } catch (Exception e) {
            return true;
        }
    }

    private Boolean isTainted(Expression expr) {
        if (expr.isNameExpr()) {
            return taintMap.getOrDefault(expr.asNameExpr().getNameAsString(), false);
        }
        // Add more logic as needed for other expression types
        return false;
    }
}
