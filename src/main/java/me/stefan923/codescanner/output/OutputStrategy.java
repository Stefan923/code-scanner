package me.stefan923.codescanner.output;

import me.stefan923.codescanner.Vulnerability;

import java.util.List;

public interface OutputStrategy {
    void print(List<Vulnerability> vulnerabilities);
}
