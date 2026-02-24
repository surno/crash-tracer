// Send SIGSEGV to self via ProcessHandle — SIGSEGV expected
// Uses ProcessHandle to get our own PID, then shells out to kill(1).
// The JVM's signal handler intercepts SIGSEGV and writes hs_err_pid
// before terminating.

public class KillSelf {
    public static void main(String[] args) throws Exception {
        long pid = ProcessHandle.current().pid();
        System.err.println("[java/kill_self] Sending SIGSEGV to self (pid=" + pid + ")...");

        // Use kill(1) since Java has no direct signal API
        new ProcessBuilder("kill", "-SEGV", String.valueOf(pid))
            .inheritIO()
            .start()
            .waitFor();
    }
}
