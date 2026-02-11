#!/usr/bin/env python3
"""Unhandled Python exception - NO signal expected.

Python exceptions are entirely managed by the interpreter. The process
exits with code 1 and a traceback on stderr. No signal is involved.
crash-tracer will NOT see this at all - it's invisible at the signal level.
This is the most common "crash" in Python and we can't catch it without
uprobe on PyErr_SetObject or similar.
"""
import sys

print("[python/unhandled_exception] Raising an unhandled RuntimeError...", file=sys.stderr)

def load_config(path):
    def parse_yaml(data):
        raise RuntimeError(f"Failed to parse config: invalid YAML at line 42")
    with open("/dev/null") as f:
        return parse_yaml(f.read())

load_config("/etc/myapp.yaml")
