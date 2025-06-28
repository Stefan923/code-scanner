package me.stefan923.codescanner.visitor;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import java.util.*;

public class MethodTaintAnalyzer {
    private final Map<String, Map<String, Boolean>> methodTaintCache = new HashMap<>();

    public Map<String, Boolean> analyzeMethod(MethodDeclaration md) {
        String methodSignature = md.getDeclarationAsString();
        if (methodTaintCache.containsKey(methodSignature)) {
            return methodTaintCache.get(methodSignature);
        }
        Map<String, Boolean> taintMap = new HashMap<>();
        md.getBody().ifPresent(body -> body.accept(new TaintTrackingVisitor(), taintMap));
        methodTaintCache.put(methodSignature, taintMap);
        return taintMap;
    }

    public Map<String, Boolean> analyzeAllMethods(CompilationUnit cu) {
        Map<String, Boolean> globalTaint = new HashMap<>();
        cu.findAll(MethodDeclaration.class).forEach(md -> {
            Map<String, Boolean> methodTaint = analyzeMethod(md);
            globalTaint.putAll(methodTaint);
        });
        return globalTaint;
    }
}
