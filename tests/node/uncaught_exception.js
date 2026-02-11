// Uncaught exception - NO signal expected
// Node.js handles this entirely in JS-land. The process exits with code 1,
// NOT via a signal. crash-tracer should NOT see this as a crash.
// This is a key false-negative test: a real application error that produces
// no signal at all.

console.error("[node/uncaught_exception] Throwing an unhandled Error...");

function deepCall(n) {
    if (n === 0) {
        throw new Error("Unhandled application error: database connection failed");
    }
    return deepCall(n - 1);
}

// Build up a realistic call stack
deepCall(10);
