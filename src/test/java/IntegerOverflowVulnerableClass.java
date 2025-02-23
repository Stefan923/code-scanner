public class IntegerOverflowVulnerableClass {
    public void vulnerableCalculationWithVariables() {
        int a = 100000;  // A large number.
        int b = 30000;   // Another large number.

        // Multiplying these numbers yields 3,000,000,000,
        // which is greater than Integer.MAX_VALUE (2,147,483,647) causing an overflow.
        int result = a * b;
        System.out.println("Result: " + result);
    }

    public void vulnerableCalculation() {
        int result = 100000 * 30000;
        System.out.println("Result: " + result);
    }

    public void executeOverflow() {
        IntegerOverflowVulnerableClass obj = new IntegerOverflowVulnerableClass();
        obj.vulnerableCalculation();
    }
}
