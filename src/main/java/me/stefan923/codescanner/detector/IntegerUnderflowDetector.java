package me.stefan923.codescanner.detector;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import me.stefan923.codescanner.Vulnerability;

import java.math.BigInteger;
import java.util.*;

public class IntegerUnderflowDetector implements VulnerabilityDetector {

    @Override
    public List<Vulnerability> detect(Node node, Map<String, Boolean> taintMap) {
        List<Vulnerability> underflowVulnerabilities = new ArrayList<>();

        if (node instanceof BinaryExpr bin) {
            BinaryExpr.Operator op = bin.getOperator();

            // Skip string concatenation
            if (op == BinaryExpr.Operator.PLUS &&
                    (bin.getLeft().isStringLiteralExpr() || bin.getRight().isStringLiteralExpr())) {
                return underflowVulnerabilities;
            }

            // Only consider arithmetic ops
            if (op == BinaryExpr.Operator.PLUS
                    || op == BinaryExpr.Operator.MINUS
                    || op == BinaryExpr.Operator.MULTIPLY) {

                Optional<BigInteger> leftVal  = evaluateNumericLiteral(bin.getLeft());
                Optional<BigInteger> rightVal = evaluateNumericLiteral(bin.getRight());

                if (leftVal.isPresent() && rightVal.isPresent()) {
                    BigInteger result = switch (op) {
                        case PLUS     -> leftVal.get().add(rightVal.get());
                        case MINUS    -> leftVal.get().subtract(rightVal.get());
                        case MULTIPLY -> leftVal.get().multiply(rightVal.get());
                        default       -> null;
                    };

                    // Underflow: result below Integer.MIN_VALUE
                    if (result != null
                            && result.compareTo(BigInteger.valueOf(Integer.MIN_VALUE)) < 0) {
                        String className = getEnclosingClassName(bin);
                        int line = bin.getBegin().map(p -> p.line).orElse(-1);
                        underflowVulnerabilities.add(new Vulnerability(
                                "Integer Underflow",
                                "Arithmetic operation `" + bin + "` underflows int range (result = " + result + ").",
                                className,
                                line
                        ));
                    }
                } else {
                    // Potential underflow if any operand is tainted
                    if (isTainted(bin.getLeft(), taintMap) || isTainted(bin.getRight(), taintMap)) {
                        String className = getEnclosingClassName(bin);
                        int line = bin.getBegin().map(p -> p.line).orElse(-1);
                        underflowVulnerabilities.add(new Vulnerability(
                                "Integer Underflow",
                                "Arithmetic operation `" + bin + "` may underflow due to tainted numeric input.",
                                className,
                                line
                        ));
                    }
                }
            }
        }

        return underflowVulnerabilities;
    }

    /**
     * Attempts to evaluate an expression to a numeric constant.
     * Supports int/long literals, simple binary arithmetic, and
     * resolving local final variables with literal initializers.
     */
    private Optional<BigInteger> evaluateNumericLiteral(Expression expr) {
        if (expr.isIntegerLiteralExpr()) {
            try {
                int v = Integer.parseInt(expr.asIntegerLiteralExpr().getValue());
                return Optional.of(BigInteger.valueOf(v));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        }
        if (expr.isLongLiteralExpr()) {
            String s = expr.asLongLiteralExpr().getValue();
            if (s.endsWith("L") || s.endsWith("l")) {
                s = s.substring(0, s.length() - 1);
            }
            try {
                long v = Long.parseLong(s);
                return Optional.of(BigInteger.valueOf(v));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        }
        if (expr.isNameExpr()) {
            return getConstantValueForVariable(expr.asNameExpr().getNameAsString(), expr);
        }
        if (expr.isBinaryExpr()) {
            BinaryExpr bin = expr.asBinaryExpr();
            // skip string concat
            if (bin.getOperator() == BinaryExpr.Operator.PLUS &&
                    (bin.getLeft().isStringLiteralExpr() || bin.getRight().isStringLiteralExpr())) {
                return Optional.empty();
            }
            Optional<BigInteger> L = evaluateNumericLiteral(bin.getLeft());
            Optional<BigInteger> R = evaluateNumericLiteral(bin.getRight());
            if (L.isPresent() && R.isPresent()) {
                return switch (bin.getOperator()) {
                    case PLUS     -> Optional.of(L.get().add(R.get()));
                    case MINUS    -> Optional.of(L.get().subtract(R.get()));
                    case MULTIPLY -> Optional.of(L.get().multiply(R.get()));
                    default       -> Optional.empty();
                };
            }
        }
        return Optional.empty();
    }

    /**
     * Finds a final or literal-initialized variable in the same method.
     */
    private Optional<BigInteger> getConstantValueForVariable(String varName, Node ctx) {
        Optional<MethodDeclaration> mDecl = ctx.findAncestor(MethodDeclaration.class);
        if (mDecl.isEmpty()) return Optional.empty();

        List<VariableDeclarator> vars =
                mDecl.get().findAll(VariableDeclarator.class,
                        v -> v.getNameAsString().equals(varName));

        for (VariableDeclarator vd : vars) {
            if (vd.getInitializer().isPresent()) {
                Optional<BigInteger> val = evaluateNumericLiteral(vd.getInitializer().get());
                if (val.isPresent()) return val;
            }
        }
        return Optional.empty();
    }

    /**
     * Simple taint check: propagates through names, binary exprs,
     * and flags common input calls.
     */
    private boolean isTainted(Expression expr, Map<String, Boolean> taintMap) {
        if (expr.isNameExpr()) {
            return taintMap.getOrDefault(expr.asNameExpr().getNameAsString(), false);
        }
        if (expr.isBinaryExpr()) {
            BinaryExpr bin = expr.asBinaryExpr();
            return isTainted(bin.getLeft(), taintMap) || isTainted(bin.getRight(), taintMap);
        }
        if (expr.isMethodCallExpr()) {
            String call = expr.asMethodCallExpr().getNameAsString();
            return call.equals("getParameter")
                    || call.equals("nextLine")
                    || call.equals("readLine");
        }
        for (Node child : expr.getChildNodes()) {
            if (child instanceof Expression && isTainted((Expression) child, taintMap)) {
                return true;
            }
        }
        return false;
    }

    private String getEnclosingClassName(Node node) {
        return node.findAncestor(ClassOrInterfaceDeclaration.class)
                .map(ClassOrInterfaceDeclaration::getNameAsString)
                .orElse("<unknown>");
    }
}
