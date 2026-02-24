// Out of memory — SIGABRT expected (with -XX:+CrashOnOutOfMemoryError)
// By default OOM just throws OutOfMemoryError (no signal). With
// -XX:+CrashOnOutOfMemoryError the JVM calls abort() and writes an
// hs_err_pid file. Run with:
//   java -XX:+CrashOnOutOfMemoryError -Xmx32m OomCrash
// crash-tracer SHOULD capture this as signal=6.

import java.util.ArrayList;

public class OomCrash {
    public static void main(String[] args) {
        System.err.println("[java/oom_crash] Exhausting heap (expects -XX:+CrashOnOutOfMemoryError -Xmx32m)...");

        ArrayList<byte[]> leak = new ArrayList<>();
        while (true) {
            leak.add(new byte[1024 * 1024]); // 1 MB at a time
        }
    }
}
