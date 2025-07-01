package me.stefan923.codescanner.output;

import me.stefan923.codescanner.Vulnerability;

import java.util.List;

public class ConsoleOutputStrategy implements OutputStrategy {

    @Override
    public void print(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities.isEmpty()) {
            System.out.println("No vulnerabilities detected.");
        } else {
            System.out.println("Detected vulnerabilities:");
            for (Vulnerability v : vulnerabilities) {
                System.out.println(v);
            }
        }
    }
}
