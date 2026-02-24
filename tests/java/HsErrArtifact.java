// Crash with hs_err_pid artifact in a specific directory — SIGSEGV expected
// Run with: java -XX:ErrorFile=/tmp/crash-tracer/hs_err_pid%p.log HsErrArtifact
// This directs the HotSpot error log to the crash-tracer output directory,
// exercising the artifact tracking path (sys_enter_openat → "hs_err_pid" match).

import java.lang.reflect.Field;
import sun.misc.Unsafe;

public class HsErrArtifact {
    public static void main(String[] args) throws Exception {
        System.err.println("[java/hs_err_artifact] Crashing with -XX:ErrorFile to /tmp/crash-tracer/...");
        System.err.println("[java/hs_err_artifact] Run with: java -XX:ErrorFile=/tmp/crash-tracer/hs_err_pid%p.log HsErrArtifact");

        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        Unsafe unsafe = (Unsafe) f.get(null);

        unsafe.putLong(0, 0xDEAD);
    }
}
