package me.stefan923.codescanner;

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import me.stefan923.codescanner.visitor.VulnerabilityVisitor;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Analyzer class that parses Java source code using JavaParser and checks for vulnerabilities:
 * SQL Injection, XSS, CSRF, and Buffer Overflow.
 */
public class Main {

    public static void main(String[] args) {
        String sourceFile = args.length > 0 ? args[0] : "../BenchmarkJava";
        String action = args.length > 1 ? args[1].toLowerCase() : "benchmark";

        if (!action.equals("benchmark") && !action.equals("suggest-fixes")) {
            System.err.println("Invalid action: " + action);
            System.err.println("Valid actions: benchmark | suggest-fixes");
            return;
        }

        File sourceDir = new File(sourceFile);
        if (!sourceDir.exists() || !sourceDir.isDirectory()) {
            System.err.println("Invalid source path: " + sourceFile);
            return;
        }

        CombinedTypeSolver typeSolver = new CombinedTypeSolver();
        typeSolver.add(new ReflectionTypeSolver());
        typeSolver.add(new JavaParserTypeSolver(sourceDir));

        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(typeSolver);
        ParserConfiguration parserConfig = new ParserConfiguration()
                .setSymbolResolver(symbolSolver);
        StaticJavaParser.setConfiguration(parserConfig);

        List<File> javaFiles = new ArrayList<>();
        collectJavaFiles(sourceDir, javaFiles);

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Process each Java file
        for (File file : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(file);
                VulnerabilityVisitor visitor = new VulnerabilityVisitor(vulnerabilities);
                visitor.visit(cu, null);
            } catch (Exception e) {
                System.err.println("Error parsing file: " + file.getAbsolutePath());
                e.printStackTrace();
            }
        }

        if (vulnerabilities.isEmpty()) {
            System.out.println("No vulnerabilities detected.");
        } else {
            System.out.println("Detected vulnerabilities:");
            for (Vulnerability v : vulnerabilities) {
                System.out.println(v);
            }
        }
    }

    private static void collectJavaFiles(File dir, List<File> javaFiles) {
        if (dir.isFile() && dir.getName().endsWith(".java")) {
            javaFiles.add(dir);
        } else if (dir.isDirectory()) {
            for (File file : Objects.requireNonNull(dir.listFiles())) {
                collectJavaFiles(file, javaFiles);
            }
        }
    }
}
