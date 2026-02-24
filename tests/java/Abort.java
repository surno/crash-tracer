// Runtime.halt(-1) — SIGABRT expected
// halt() bypasses shutdown hooks and calls _exit, but with a negative
// status the JVM calls abort() internally.
// crash-tracer SHOULD capture this as signal=6.

public class Abort {
    public static void main(String[] args) {
        System.err.println("[java/abort] Calling Runtime.halt(-1)...");
        Runtime.getRuntime().halt(-1);
    }
}
