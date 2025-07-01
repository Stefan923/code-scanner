package me.stefan923.codescanner;

import me.stefan923.codescanner.metrics.ScanMetrics;
import me.stefan923.codescanner.output.ConsoleOutputStrategy;
import me.stefan923.codescanner.output.JsonOutputStrategy;
import me.stefan923.codescanner.output.OutputStrategy;

import java.io.File;
import java.util.*;

public class Main {

    public static void main(String[] args) {
        String sourcePath = args.length > 0 ? args[0] : "../BenchmarkJava";
        String action = args.length > 1 ? args[1].toLowerCase() : "benchmark";
        String outputType = args.length > 2 ? args[2].toLowerCase() : "console";

        if (!List.of("benchmark", "suggest-fixes").contains(action)) {
            System.err.println("Invalid action: " + action);
            return;
        }

        File sourceDir = new File(sourcePath);
        if (!sourceDir.exists() || !sourceDir.isDirectory()) {
            System.err.println("Invalid source path: " + sourcePath);
            return;
        }

        ScanMetrics metrics = new ScanMetrics();
        metrics.start();

        JavaFileScanner scanner = new JavaFileScanner(sourceDir, metrics);
        List<Vulnerability> vulnerabilities = scanner.scan();

        metrics.end();

        OutputStrategy output = createOutputStrategy(outputType);
        if (output == null) {
            System.err.println("Invalid output type: " + outputType);
            return;
        }

        metrics.printSummary();
        output.print(vulnerabilities);
    }

    private static OutputStrategy createOutputStrategy(String type) {
        return switch (type) {
            case "console" -> new ConsoleOutputStrategy();
            case "json" -> new JsonOutputStrategy();
            default -> null;
        };
    }
}
