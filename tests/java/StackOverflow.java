// Stack overflow — NO signal expected
// The JVM detects stack overflow via guard pages internally and throws
// StackOverflowError, a normal Java exception. The SIGSEGV on the guard
// page is caught by the JVM's own signal handler and converted to the
// Java exception. crash-tracer may see a transient SIGSEGV — this is a
// key FALSE POSITIVE scenario (same as V8/Node).

public class StackOverflow {
    public static void main(String[] args) {
        System.err.println("[java/stack_overflow] Recursing until JVM stack limit...");

        try {
            recurse(0);
        } catch (StackOverflowError e) {
            System.err.println("[java/stack_overflow] JVM caught it as StackOverflowError");
            System.err.println("[java/stack_overflow] Process survived - no real crash occurred");
        }
    }

    static int recurse(int n) {
        return recurse(n + 1);
    }
}
