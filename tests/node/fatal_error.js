// V8 heap exhaustion - SIGABRT expected
// When V8 runs out of memory, it calls V8::FatalProcessOutOfMemory which
// eventually triggers abort(). crash-tracer should see SIGABRT.
// Note: V8 may use internal signals during GC pressure before the actual abort.
// Those internal signals are false positives.

console.error("[node/fatal_error] Exhausting V8 heap (this may take a moment)...");

const arrays = [];
try {
    while (true) {
        // Allocate ~10MB chunks to exhaust heap quickly
        arrays.push(new Array(1024 * 1024).fill("x".repeat(10)));
    }
} catch (e) {
    // V8 may throw a RangeError or similar before aborting
    console.error(`[node/fatal_error] Caught: ${e.message}`);
    console.error("[node/fatal_error] Continuing to force OOM...");

    // Try harder - allocate Buffers which are off-V8-heap but still tracked
    const buffers = [];
    while (true) {
        buffers.push(Buffer.alloc(100 * 1024 * 1024));
    }
}
