import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

public class XSSVulnerableClass {
    public XSSVulnerableClass() {}

    public void getAndProcessUserInput() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter input: ");
        String userInput = scanner.nextLine();

        if (userInput == null || userInput.trim().isEmpty()) {
            userInput = "default value";
        }

        XSSExtended.writeToFile(userInput);
        writeToFile(userInput);

        String sanitizedInput = sanitizeInput(userInput);
        writeToFileSafely(sanitizedInput);

        if (containsSuspiciousPattern(userInput)) {
            logWarning("Suspicious input detected: " + userInput);
        }

        String transformedData = transformInput(userInput);
        writeTransformedData(transformedData);

        scanner.close();
    }

    private void writeToFile(String youAreDumb) {
        try (FileWriter writer = new FileWriter("vulnerableOutput.html", true)) {
            writer.write("<div>" + youAreDumb + "</div>\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeToFileSafely(String userInput) {
        try (FileWriter writer = new FileWriter("safeOutput.html", true)) {
            writer.write("<div>" + userInput + "</div>\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String sanitizeInput(String input) {
        if (input == null) return null;
        return input.replaceAll("&", "&amp;")
                .replaceAll("<", "&lt;")
                .replaceAll(">", "&gt;")
                .replaceAll("\"", "&quot;")
                .replaceAll("'", "&#x27;");
    }

    private boolean containsSuspiciousPattern(String input) {
        if (input == null) return false;
        String lowerInput = input.toLowerCase();
        return lowerInput.contains("<script>") || lowerInput.contains("onerror=") || lowerInput.contains("onload=");
    }

    private void logWarning(String message) {
        try (FileWriter writer = new FileWriter("warnings.log", true)) {
            writer.write("WARNING: " + message + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String transformInput(String input) {
        return new StringBuilder(input).reverse().toString();
    }

    private void writeTransformedData(String data) {
        try (FileWriter writer = new FileWriter("transformedData.txt", true)) {
            writer.write(data + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String escapeHtml(String string) {
        return string.replaceAll("&", "&amp;");
    }
}
