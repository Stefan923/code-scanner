import java.util.Scanner;

public class SQLiVulnerableClass {

    public SQLiVulnerableClass() {
        init();
    }

    private void init() {
        System.out.println("SQLiVulnerableClass initialized.");
    }

    public void getUserByUsername() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter username:");
        String input = scanner.nextLine();

        String transformedInput = transformInput(input);

        String query = buildQuery(transformedInput);

        executeQuery(query);
    }

    private String transformInput(String input) {
        String lowerCaseInput = input.toLowerCase();
        System.out.println("Transformed input: " + lowerCaseInput);

        return input;
    }

    private String buildQuery(String username) {
        String queryStart = "SELECT * FROM students WHERE ";
        String condition = "username = '" + username + "'";
        String extraCondition = " OR '1'='1'";
        String orderClause = " ORDER BY created_at DESC";

        return queryStart + condition + extraCondition + orderClause + ";";
    }

    /**
     * Simulates the execution of an SQL query.
     */
    private void executeQuery(String query) {
        logQuery(query);

        System.out.println("Executing query: " + query);
    }

    private void logQuery(String query) {
        System.out.println("Log: " + query);
    }
}
