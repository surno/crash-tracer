#!/usr/bin/env python3
"""SIGABRT via os.abort() - SIGABRT expected.

Directly calls abort(), bypassing Python's exception handling entirely.
crash-tracer SHOULD capture signal=6.
This simulates a fatal error in a C extension that calls abort().
"""
import sys
import os

print("[python/abort_signal] Calling os.abort()...", file=sys.stderr)
sys.stderr.flush()

os.abort()
