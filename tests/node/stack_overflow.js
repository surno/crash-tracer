// Stack overflow - NO signal expected (usually)
// V8 detects stack overflow via guard pages internally and throws a
// RangeError: Maximum call stack size exceeded.
// This is handled WITHIN V8 - the SIGSEGV on the guard page is caught by
// V8's own signal handler and converted to a JS exception.
// crash-tracer may see a transient SIGSEGV that V8 handles - this is a
// key FALSE POSITIVE scenario.

console.error("[node/stack_overflow] Recursing until V8 stack limit...");

function recurse(n) {
    return recurse(n + 1);
}

try {
    recurse(0);
} catch (e) {
    console.error(`[node/stack_overflow] V8 caught it as JS exception: ${e.message}`);
    console.error("[node/stack_overflow] Process survived - no real crash occurred");
}
