#!/usr/bin/env python3
"""Stack overflow via recursion - NO signal expected (usually).

Python has a configurable recursion limit (default 1000). When exceeded,
Python raises RecursionError - a regular Python exception, NOT a signal.
CPython detects this before hitting the actual OS stack limit.

crash-tracer will NOT see this. It's handled entirely in Python-land.

If you set sys.setrecursionlimit() very high, Python might actually
exhaust the OS stack and SIGSEGV, but the default limit prevents that.
"""
import sys

print("[python/stack_overflow] Recursing past Python's recursion limit...", file=sys.stderr)
print(f"[python/stack_overflow] Current limit: {sys.getrecursionlimit()}", file=sys.stderr)

def recurse(n):
    return recurse(n + 1)

try:
    recurse(0)
except RecursionError as e:
    print(f"[python/stack_overflow] Python caught it: {e}", file=sys.stderr)
    print("[python/stack_overflow] No signal generated - process survived", file=sys.stderr)
