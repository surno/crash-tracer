// Unhandled promise rejection - NO signal expected
// Since Node 15+, unhandled rejections terminate the process with exit code 1.
// Like uncaught exceptions, this is a JS-level error with no signal.
// crash-tracer won't see it without uprobe/USDT integration.

console.error("[node/unhandled_rejection] Creating an unhandled promise rejection...");

async function fetchUser(id) {
    // Simulated async failure
    throw new Error(`Failed to fetch user ${id}: connection timeout`);
}

// No .catch() - this rejection is unhandled
fetchUser(42);

// Keep the event loop alive briefly so the rejection fires
setTimeout(() => {}, 100);
