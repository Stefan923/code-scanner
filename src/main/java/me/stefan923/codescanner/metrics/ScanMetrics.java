package me.stefan923.codescanner.metrics;

import java.util.HashMap;
import java.util.Map;

public class ScanMetrics {
    private int filesScanned = 0;
    private int filesWithErrors = 0;
    private int filesWithVulnerabilities = 0;
    private int totalLines = 0;
    private long startTime;
    private long endTime;

    private final Map<String, Integer> vulnerabilityCounts = new HashMap<>();

    public void start() {
        startTime = System.currentTimeMillis();
    }

    public void end() {
        endTime = System.currentTimeMillis();
    }

    public void incrementFilesScanned() {
        filesScanned++;
    }

    public void incrementFilesWithErrors() {
        filesWithErrors++;
    }

    public void incrementFilesWithVulnerabilities() {
        filesWithVulnerabilities++;
    }

    public void addLines(int lines) {
        totalLines += lines;
    }

    public void recordVulnerability(String type) {
        vulnerabilityCounts.merge(type, 1, Integer::sum);
    }

    public long getElapsedTimeMillis() {
        return endTime - startTime;
    }

    public void printSummary() {
        System.out.println("\n--- Scan Summary ---");
        System.out.println("Files scanned: " + filesScanned);
        System.out.println("Files with vulnerabilities: " + filesWithVulnerabilities);
        System.out.println("Files with parsing errors: " + filesWithErrors);
        System.out.println("Total lines of code: " + totalLines);
        System.out.println("Scan time (ms): " + getElapsedTimeMillis());
        System.out.println("Vulnerabilities found: " + vulnerabilityCounts.values().stream().mapToInt(i -> i).sum());
        System.out.println("Breakdown by type:");
        vulnerabilityCounts.forEach((type, count) ->
                System.out.println(" - " + type + ": " + count));
    }
}
