package me.stefan923.codescanner;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.resolution.TypeSolver;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import me.stefan923.codescanner.visitor.VulnerabilityVisitor;

import java.io.File;
import java.util.*;

public class JavaFileScanner {
    private final File sourceDir;

    public JavaFileScanner(File sourceDir) {
        this.sourceDir = sourceDir;
        configureParser();
    }

    public List<Vulnerability> scan() {
        List<File> javaFiles = new ArrayList<>();
        collectJavaFiles(sourceDir, javaFiles);

        List<Vulnerability> vulnerabilities = new ArrayList<>();
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
        return vulnerabilities;
    }

    private void collectJavaFiles(File dir, List<File> javaFiles) {
        if (dir.isFile() && dir.getName().endsWith(".java")) {
            javaFiles.add(dir);
        } else if (dir.isDirectory()) {
            for (File file : Objects.requireNonNull(dir.listFiles())) {
                collectJavaFiles(file, javaFiles);
            }
        }
    }

    private void configureParser() {
        TypeSolver typeSolver = new CombinedTypeSolver(
                new ReflectionTypeSolver(),
                new JavaParserTypeSolver(sourceDir)
        );
        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(typeSolver);
        StaticJavaParser.getConfiguration().setSymbolResolver(symbolSolver);
    }
}
