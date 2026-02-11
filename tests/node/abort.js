// process.abort() - SIGABRT expected
// This is the Node.js equivalent of calling abort() in C.
// crash-tracer SHOULD capture this as signal=6.

console.error("[node/abort] Calling process.abort()...");
process.abort();
