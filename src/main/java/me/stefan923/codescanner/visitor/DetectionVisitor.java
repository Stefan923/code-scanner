package me.stefan923.codescanner.visitor;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import me.stefan923.codescanner.Vulnerability;
import me.stefan923.codescanner.detector.VulnerabilityDetector;

import java.util.List;
import java.util.Map;

public class DetectionVisitor extends VoidVisitorAdapter<Void> {
    private final Map<String, Boolean> taintMap;
    private final VulnerabilityDetector compositeDetector;
    private final List<Vulnerability> vulnerabilities;

    public DetectionVisitor(Map<String, Boolean> taintMap, VulnerabilityDetector compositeDetector, List<Vulnerability> vulnerabilities) {
        this.taintMap = taintMap;
        this.compositeDetector = compositeDetector;
        this.vulnerabilities = vulnerabilities;
    }

    @Override
    public void visit(MethodCallExpr mce, Void arg) {
        super.visit(mce, arg);
        vulnerabilities.addAll(compositeDetector.detect(mce, taintMap));
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
}
