// Node diagnostic report on fatal error
// Run with: node --report-on-fatalerror --report-directory=/tmp/crash-tracer/ tests/node/diagnostic_report.js
// Expected: SIGABRT + a report.*.json file in the report directory
// This demonstrates the runtime artifact that crash-tracer could collect.

console.error("[node/diagnostic_report] This test should be run with:");
console.error("  node --report-on-fatalerror --report-directory=/tmp/crash-tracer/ tests/node/diagnostic_report.js");
console.error("[node/diagnostic_report] Calling process.abort() to trigger both crash + diagnostic report...");

process.abort();
