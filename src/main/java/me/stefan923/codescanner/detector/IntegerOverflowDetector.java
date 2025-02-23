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

public class IntegerOverflowDetector implements VulnerabilityDetector {

    @Override
    public List<Vulnerability> detect(Node node, Map<String, Boolean> taintMap) {
        List<Vulnerability> integerOverflowVulnerabilities = new ArrayList<>();
        if (node instanceof BinaryExpr bin) {
            BinaryExpr.Operator op = bin.getOperator();


            if (op == BinaryExpr.Operator.PLUS &&
                    (bin.getLeft().isStringLiteralExpr() || bin.getRight().isStringLiteralExpr())) {
                return integerOverflowVulnerabilities; // Skip string concatenation.
            }
            if (op == BinaryExpr.Operator.PLUS ||
                    op == BinaryExpr.Operator.MINUS ||
                    op == BinaryExpr.Operator.MULTIPLY) {

                Optional<BigInteger> leftVal = evaluateNumericLiteral(bin.getLeft());
                Optional<BigInteger> rightVal = evaluateNumericLiteral(bin.getRight());

                if (leftVal.isPresent() && rightVal.isPresent()) {
                    BigInteger result = null;
                    switch (op) {
                        case PLUS:
                            result = leftVal.get().add(rightVal.get());
                            break;
                        case MINUS:
                            result = leftVal.get().subtract(rightVal.get());
                            break;
                        case MULTIPLY:
                            result = leftVal.get().multiply(rightVal.get());
                            break;
                        default:
                            break;
                    }
                    // Check if the result exceeds 32-bit signed integer range.
                    if (result.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0 ||
                            result.compareTo(BigInteger.valueOf(Integer.MIN_VALUE)) < 0) {
                        String className = getEnclosingClassName(bin);
                        int line = bin.getBegin().map(pos -> pos.line).orElse(-1);
                        integerOverflowVulnerabilities.add(new Vulnerability("Integer Overflow",
                                "Arithmetic operation " + bin + " overflows int range.",
                                className, line));
                    }
                } else {
                    // If not all operands can be resolved to a numeric constant,
                    // check if any operand is tainted. (If so, we flag potential risk.)
                    if (isTainted(bin.getLeft(), taintMap) || isTainted(bin.getRight(), taintMap)) {
                        String className = getEnclosingClassName(bin);
                        int line = bin.getBegin().map(pos -> pos.line).orElse(-1);
                        integerOverflowVulnerabilities.add(new Vulnerability("Integer Overflow",
                                "Arithmetic operation " + bin.toString() + " may overflow due to tainted numeric input.",
                                className, line));
                    }
                }
            }
        }
        return integerOverflowVulnerabilities;
    }

    /**
     * Evaluates an expression as a numeric literal (or a combination thereof).
     * Handles integer and long literals, binary arithmetic, and attempts to resolve variables.
     */
    private Optional<BigInteger> evaluateNumericLiteral(Expression expr) {
        if (expr.isIntegerLiteralExpr()) {
            try {
                int value = Integer.parseInt(expr.asIntegerLiteralExpr().getValue());
                return Optional.of(BigInteger.valueOf(value));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        } else if (expr.isLongLiteralExpr()) {
            try {
                String valStr = expr.asLongLiteralExpr().getValue();
                if (valStr.endsWith("L") || valStr.endsWith("l")) {
                    valStr = valStr.substring(0, valStr.length() - 1);
                }
                long value = Long.parseLong(valStr);
                return Optional.of(BigInteger.valueOf(value));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        } else if (expr.isNameExpr()) {
            String varName = expr.asNameExpr().getNameAsString();
            return getConstantValueForVariable(varName, expr);
        } else if (expr.isBinaryExpr()) {
            BinaryExpr bin = expr.asBinaryExpr();
            // If PLUS operator involves a string literal, skip.
            if (bin.getOperator() == BinaryExpr.Operator.PLUS &&
                    (bin.getLeft().isStringLiteralExpr() || bin.getRight().isStringLiteralExpr())) {
                return Optional.empty();
            }
            Optional<BigInteger> left = evaluateNumericLiteral(bin.getLeft());
            Optional<BigInteger> right = evaluateNumericLiteral(bin.getRight());
            if (left.isPresent() && right.isPresent()) {
                switch (bin.getOperator()) {
                    case PLUS:
                        return Optional.of(left.get().add(right.get()));
                    case MINUS:
                        return Optional.of(left.get().subtract(right.get()));
                    case MULTIPLY:
                        return Optional.of(left.get().multiply(right.get()));
                    default:
                        return Optional.empty();
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Attempts to resolve a variable's constant numeric value by looking for its declaration
     * in the enclosing method. Only returns a value if the initializer is a numeric literal.
     */
    private Optional<BigInteger> getConstantValueForVariable(String varName, Node context) {
        Optional<MethodDeclaration> methodDecl = context.findAncestor(MethodDeclaration.class);
        if (methodDecl.isPresent()) {
            List<VariableDeclarator> vars = methodDecl.get().findAll(VariableDeclarator.class,
                    v -> v.getNameAsString().equals(varName));
            for (VariableDeclarator var : vars) {
                if (var.getInitializer().isPresent()) {
                    Optional<BigInteger> val = evaluateNumericLiteral(var.getInitializer().get());
                    if (val.isPresent()) {
                        return val;
                    }
                }
            }
        }
        return Optional.empty();
    }

    private boolean isTainted(Expression expr, Map<String, Boolean> taintMap) {
        if (expr.isNameExpr()) {
            String name = expr.asNameExpr().getNameAsString();
            return taintMap.getOrDefault(name, false);
        }
        if (expr.isBinaryExpr()) {
            BinaryExpr bin = expr.asBinaryExpr();
            return isTainted(bin.getLeft(), taintMap) || isTainted(bin.getRight(), taintMap);
        }
        if (expr.isMethodCallExpr()) {
            String callName = expr.asMethodCallExpr().getNameAsString();
            return callName.equals("getParameter") || callName.equals("nextLine") || callName.equals("readLine");
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
