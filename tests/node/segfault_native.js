// Native segfault via process.kill - SIGSEGV expected
// Sends SIGSEGV directly to self, bypassing V8's signal handler.
// crash-tracer SHOULD capture this as signal=11.
// In real-world scenarios, this happens when a native addon (C++ binding)
// has a bug - the crash is in native code, not JS.

console.error("[node/segfault_native] Sending SIGSEGV to self via process.kill...");
console.error("[node/segfault_native] This simulates a native addon crash");
process.kill(process.pid, "SIGSEGV");
