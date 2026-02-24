// Segfault via sun.misc.Unsafe — SIGSEGV expected
// Writing to address 0 via Unsafe bypasses all JVM safety checks and
// crashes the process with a real SIGSEGV. The JVM writes an hs_err_pid
// file before dying — this is the primary artifact crash-tracer tracks.

import java.lang.reflect.Field;
import sun.misc.Unsafe;

public class SegfaultUnsafe {
    public static void main(String[] args) throws Exception {
        System.err.println("[java/segfault_unsafe] Dereferencing null via sun.misc.Unsafe...");

        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        Unsafe unsafe = (Unsafe) f.get(null);

        // Write to address 0 — guaranteed SIGSEGV
        unsafe.putLong(0, 0xDEAD);
    }
}
