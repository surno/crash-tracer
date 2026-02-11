#!/usr/bin/env python3
"""Self-SIGSEGV via os.kill - SIGSEGV expected.

Sends SIGSEGV to self, bypassing Python's own handling.
crash-tracer SHOULD capture signal=11.
This simulates receiving a signal from an external source.
"""
import sys
import os
import signal

print("[python/kill_self] Sending SIGSEGV to self...", file=sys.stderr)
sys.stderr.flush()

os.kill(os.getpid(), signal.SIGSEGV)
