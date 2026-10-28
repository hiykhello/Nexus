"""Inject a failure after partial worker startup and verify rollback."""
import os
import subprocess
import sys
from pathlib import Path

binary, shim = (str(Path(arg).resolve()) for arg in sys.argv[1:3])
for mode in ("listen", "thread", "reuse"):
    env = os.environ.copy()
    env.update(LD_PRELOAD=shim, NEXUS_START_FAULT=mode)
    result = subprocess.run([binary], env=env, capture_output=True, timeout=10)
    if result.returncode or b"proxy-start-fault-injected" not in result.stderr:
        raise RuntimeError(f"{mode}: exit {result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")
    print(f"{mode}: {result.stdout.decode().strip()}")
