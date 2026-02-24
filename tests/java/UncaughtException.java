// Uncaught exception — NO signal expected
// An unhandled Java exception causes System.exit(1). The JVM shuts down
// cleanly via its normal exit path. No signal is delivered.
// crash-tracer should NOT capture this.

public class UncaughtException {
    public static void main(String[] args) {
        System.err.println("[java/uncaught_exception] Throwing an unhandled RuntimeException...");

        deepCall(10);
    }

    static void deepCall(int n) {
        if (n == 0) {
            throw new RuntimeException("Simulated application failure: connection refused");
        }
        deepCall(n - 1);
    }
}
