"""Compatibility entry point for the asynchronous Reality local DNS test.

Previously this test injected a slow getaddrinfo and reproduced delayed stop.
The Reality fallback now uses a nameserver snapshot and does not call it.
"""
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
subprocess.run([sys.executable, root/'tests/reality_inbound_local_dns.py'], check=True)
