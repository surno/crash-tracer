#!/usr/bin/env bash
#
# Runtime crash test suite for crash-tracer
#
# Usage:
#   ./tests/run_all.sh           Run all tests
#   ./tests/run_all.sh native    Run only native tests
#   ./tests/run_all.sh node      Run only Node.js tests
#   ./tests/run_all.sh python    Run only Python tests
#
# Run crash-tracer in another terminal first:
#   sudo ./target/debug/crash-tracer --verbose
#
# Then run this script and compare the crash-tracer output.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/native/bin"
DELAY=1  # seconds between tests so crash-tracer output is readable

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

run_test() {
    local name="$1"
    local expect="$2"  # "signal" or "no_signal"
    local cmd="$3"
    shift 3

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${CYAN}TEST: ${name}${RESET}"
    if [ "$expect" = "signal" ]; then
        echo -e "${RED}EXPECT: crash-tracer SHOULD capture this${RESET}"
    else
        echo -e "${GREEN}EXPECT: crash-tracer should NOT see this (no signal)${RESET}"
    fi
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${DIM}$ ${cmd} $*${RESET}"
    echo ""

    # Run the command, capturing exit status
    set +e
    "$cmd" "$@" 2>&1
    local exit_code=$?
    set -e

    echo ""
    if [ $exit_code -eq 0 ]; then
        echo -e "  ${GREEN}Exit code: ${exit_code} (clean exit)${RESET}"
    elif [ $exit_code -gt 128 ]; then
        local sig=$((exit_code - 128))
        echo -e "  ${RED}Exit code: ${exit_code} (killed by signal ${sig})${RESET}"
    else
        echo -e "  ${YELLOW}Exit code: ${exit_code} (error, but no signal)${RESET}"
    fi

    sleep "$DELAY"
}

build_native() {
    echo -e "${BOLD}Building native test programs...${RESET}"
    mkdir -p "$BUILD_DIR"

    for src in "$SCRIPT_DIR"/native/*.c; do
        local name
        name="$(basename "$src" .c)"
        gcc -O0 -g -o "$BUILD_DIR/$name" "$src"
        echo "  Built: $name"
    done
    echo ""
}

run_native() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║  NATIVE (C) TESTS                                          ║${RESET}"
    echo -e "${BOLD}║  All of these produce real signals. crash-tracer should     ║${RESET}"
    echo -e "${BOLD}║  capture every one.                                         ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"

    build_native

    run_test "native/segfault (SIGSEGV - null deref)"        signal "$BUILD_DIR/segfault"
    run_test "native/abort (SIGABRT)"                        signal "$BUILD_DIR/abort"
    run_test "native/divzero (SIGFPE)"                       signal "$BUILD_DIR/divzero"
    run_test "native/illegal_instruction (SIGILL)"           signal "$BUILD_DIR/illegal_instruction"
    run_test "native/stack_overflow (SIGSEGV - stack)"       signal "$BUILD_DIR/stack_overflow"
    run_test "native/bus_error (SIGBUS)"                     signal "$BUILD_DIR/bus_error"
    run_test "native/use_after_free (SIGSEGV - maybe)"       signal "$BUILD_DIR/use_after_free"
}

run_node() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║  NODE.JS (V8) TESTS                                        ║${RESET}"
    echo -e "${BOLD}║  Mix of signal and non-signal exits. Watch for false        ║${RESET}"
    echo -e "${BOLD}║  positives from V8's internal signal handling.              ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"

    run_test "node/uncaught_exception (JS Error - no signal)"      no_signal node "$SCRIPT_DIR/node/uncaught_exception.js"
    run_test "node/unhandled_rejection (Promise - no signal)"      no_signal node "$SCRIPT_DIR/node/unhandled_rejection.js"
    run_test "node/stack_overflow (V8 catches internally)"         no_signal node "$SCRIPT_DIR/node/stack_overflow.js"
    run_test "node/abort (process.abort - SIGABRT)"                signal    node "$SCRIPT_DIR/node/abort.js"
    run_test "node/segfault_native (kill -SEGV self)"              signal    node "$SCRIPT_DIR/node/segfault_native.js"
    run_test "node/fatal_error (V8 OOM - SIGABRT)"                signal    node --max-old-space-size=50 "$SCRIPT_DIR/node/fatal_error.js"
    run_test "node/diagnostic_report (abort + report.json)"        signal    node --report-on-fatalerror --report-directory=/tmp/crash-tracer/ "$SCRIPT_DIR/node/diagnostic_report.js"
}

run_python() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║  PYTHON (CPython) TESTS                                    ║${RESET}"
    echo -e "${BOLD}║  Python exceptions produce NO signals. Only crashes in      ║${RESET}"
    echo -e "${BOLD}║  native code (ctypes, C extensions) produce signals.        ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"

    run_test "python/unhandled_exception (Python Error - no signal)"   no_signal python3 "$SCRIPT_DIR/python/unhandled_exception.py"
    run_test "python/stack_overflow (RecursionError - no signal)"      no_signal python3 "$SCRIPT_DIR/python/stack_overflow.py"
    run_test "python/segfault_ctypes (SIGSEGV via ctypes)"             signal    python3 "$SCRIPT_DIR/python/segfault_ctypes.py"
    run_test "python/faulthandler_crash (SIGSEGV + Python traceback)"  signal    python3 "$SCRIPT_DIR/python/faulthandler_crash.py"
    run_test "python/abort_signal (SIGABRT via os.abort)"              signal    python3 "$SCRIPT_DIR/python/abort_signal.py"
    run_test "python/kill_self (SIGSEGV via os.kill)"                  signal    python3 "$SCRIPT_DIR/python/kill_self.py"
}

# --- Main ---

echo -e "${BOLD}crash-tracer runtime test suite${RESET}"
echo -e "${DIM}Make sure crash-tracer is running: sudo ./target/debug/crash-tracer --verbose${RESET}"
echo ""

filter="${1:-all}"

case "$filter" in
    native)  run_native ;;
    node)    run_node ;;
    python)  run_python ;;
    all)
        run_native
        run_node
        run_python
        echo ""
        echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
        echo -e "${BOLD}ALL TESTS COMPLETE${RESET}"
        echo ""
        echo "Summary of what crash-tracer should have captured:"
        echo "  Native:  segfault, abort, divzero, illegal_instruction, stack_overflow, bus_error"
        echo "           (use_after_free is non-deterministic)"
        echo "  Node.js: abort, segfault_native, fatal_error, diagnostic_report"
        echo "           (NOT: uncaught_exception, unhandled_rejection, stack_overflow)"
        echo "  Python:  segfault_ctypes, faulthandler_crash, abort_signal, kill_self"
        echo "           (NOT: unhandled_exception, stack_overflow)"
        echo ""
        echo "Check /tmp/crash-tracer/ for generated crash reports."
        echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
        ;;
    *)
        echo "Usage: $0 [native|node|python|all]"
        exit 1
        ;;
esac
