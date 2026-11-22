#!/usr/bin/env python3
"""Compare deterministic 8 KiB writes with pinned Xray's real VisionWriter."""
import pathlib
import subprocess
import sys

root=pathlib.Path(__file__).resolve().parents[1]
fixture=pathlib.Path(sys.argv[1]).resolve()
for mode in ("direct", "end", "plain", "records"):
    expected=subprocess.run(["go","run","./writer",mode],cwd=root/"experiments/vision-vector",check=True,capture_output=True).stdout
    actual=subprocess.run([fixture,mode],check=True,capture_output=True).stdout
    if actual!=expected:
        mismatch=next((i for i,(a,b) in enumerate(zip(actual,expected)) if a!=b),min(len(actual),len(expected)))
        raise RuntimeError(f"{mode}: mismatch at {mismatch}, Nexus {len(actual)} bytes, Xray {len(expected)} bytes")
print("Vision 8 KiB direct, end, non-TLS, and two-record writes match pinned Xray VisionWriter")
