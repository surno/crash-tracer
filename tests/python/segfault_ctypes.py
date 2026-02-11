#!/usr/bin/env python3
"""Native segfault via ctypes - SIGSEGV expected.

Uses ctypes to write to address 0, causing a real SIGSEGV in the CPython
process. This simulates what happens when a C extension (numpy, pillow,
native binding) has a bug. crash-tracer SHOULD capture signal=11.

The crash will be in native code - the Python stack is lost without
faulthandler. Compare with faulthandler_crash.py to see the difference.
"""
import sys
import ctypes

print("[python/segfault_ctypes] Writing to NULL via ctypes...", file=sys.stderr)
sys.stderr.flush()

ctypes.string_at(0, 1)
