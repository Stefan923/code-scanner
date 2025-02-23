package me.stefan923.codescanner.detector;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.ArrayCreationExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import me.stefan923.codescanner.Vulnerability;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class BufferOverflowDetector implements VulnerabilityDetector {
    @Override
    public List<Vulnerability> detect(Node node, Map<String, Boolean> taintMap) {
        List<Vulnerability> bufferOverflowVulnerabilities = new ArrayList<>();
        if (node instanceof MethodCallExpr mce) {
            String methodName = mce.getNameAsString();
            if (methodName.contains("copy") || methodName.contains("buffer")) {
                if (mce.getArguments().size() >= 4) {
                    Expression destExpr = mce.getArgument(1);
                    Expression startExpr = mce.getArgument(2);
                    Expression countExpr = mce.getArgument(3);
                    Optional<Integer> destSize = Optional.empty();
                    if (destExpr.isNameExpr()) {
                        destSize = getArraySizeForVariable(destExpr.asNameExpr().getNameAsString(), mce);
                    }
                    Optional<Integer> startOpt = getIntegerLiteral(startExpr);
                    Optional<Integer> countOpt = getIntegerLiteral(countExpr);
                    String className = getEnclosingClassName(mce);
                    int line = mce.getBegin().map(p -> p.line).orElse(-1);
                    if (destSize.isPresent() && startOpt.isPresent() && countOpt.isPresent()) {
                        int destSizeVal = destSize.get();
                        int start = startOpt.get();
                        int count = countOpt.get();
                        if (start + count > destSizeVal) {
                            bufferOverflowVulnerabilities.add(new Vulnerability("Buffer Overflow",
                                    "Method call " + methodName + " causes buffer overflow: "
                                            + (start + count) + " exceeds destination size " + destSizeVal,
                                    className, line));
                        }
                    } else {
                        bufferOverflowVulnerabilities.add(new Vulnerability("Buffer Overflow",
                                "Method call " + methodName + " might be prone to buffer overflow (unable to verify bounds).",
                                className, line));
                    }
                } else {
                    String className = getEnclosingClassName(mce);
                    int line = mce.getBegin().map(p -> p.line).orElse(-1);
                    bufferOverflowVulnerabilities.add(new Vulnerability("Buffer Overflow",
                            "Method call " + methodName + " might be prone to buffer overflow (insufficient arguments).",
                            className, line));
                }
            }
        }
        return bufferOverflowVulnerabilities;
    }

    private Optional<Integer> getIntegerLiteral(Expression expr) {
        if (expr.isIntegerLiteralExpr()) {
            try {
                int value = Integer.parseInt(expr.asIntegerLiteralExpr().getValue());
                return Optional.of(value);
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    private Optional<Integer> getArraySizeForVariable(String varName, Node node) {
        Optional<MethodDeclaration> md = node.findAncestor(MethodDeclaration.class);
        if (md.isPresent()) {
            List<VariableDeclarator> vars = md.get().findAll(VariableDeclarator.class,
                    v -> v.getNameAsString().equals(varName));
            for (VariableDeclarator var : vars) {
                if (var.getInitializer().isPresent() && var.getInitializer().get().isArrayCreationExpr()) {
                    ArrayCreationExpr ace = var.getInitializer().get().asArrayCreationExpr();
                    if (!ace.getLevels().isEmpty() && ace.getLevels().get(0).getDimension().isPresent()) {
                        Expression dimExpr = ace.getLevels().get(0).getDimension().get();
                        return getIntegerLiteral(dimExpr);
                    }
                }
            }
        }
        return Optional.empty();
    }

    private String getEnclosingClassName(Node node) {
        Optional<ClassOrInterfaceDeclaration> cid = node.findAncestor(ClassOrInterfaceDeclaration.class);
        return cid.map(ClassOrInterfaceDeclaration::getNameAsString).orElse("<unknown>");
    }
}
