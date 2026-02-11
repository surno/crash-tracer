#!/usr/bin/env python3
"""Segfault WITH faulthandler enabled - SIGSEGV expected + Python traceback on stderr.

When faulthandler is enabled, Python installs its own signal handler for
SIGSEGV/SIGABRT/etc. On crash, it prints the Python stack trace to stderr
BEFORE dying. This is the Python equivalent of JVM's hs_err_pid file.

crash-tracer will see the SIGSEGV. The faulthandler output goes to stderr
(not a file), so collecting it requires capturing the process's stderr.

Compare the crash-tracer output between this and segfault_ctypes.py -
the signal-level data is identical, but this one has a Python traceback
on stderr that crash-tracer currently can't capture.
"""
import sys
import faulthandler
import ctypes

# Enable faulthandler - this is what makes the difference
faulthandler.enable()

print("[python/faulthandler_crash] faulthandler enabled, crashing via ctypes...", file=sys.stderr)
sys.stderr.flush()

def process_data(data):
    def inner_transform(buf):
        # Simulate a bug in native code called from Python
        ctypes.string_at(0, 1)
    return inner_transform(data)

process_data(b"hello")
