package me.stefan923.codescanner.output;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import me.stefan923.codescanner.Vulnerability;

import java.util.List;

public class JsonOutputStrategy implements OutputStrategy {

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    @Override
    public void print(List<Vulnerability> vulnerabilities) {
        System.out.println(gson.toJson(vulnerabilities));
    }
}
