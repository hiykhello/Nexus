"""Check context initialization errors in the API and the real CLI."""
import os
from pathlib import Path
import subprocess
import sys

api, cli, shim = (str(Path(arg).resolve()) for arg in sys.argv[1:4])
for mode in ("uring-setup", "uring-eventfd", "uring-submit"):
    env = os.environ.copy()
    env.update(LD_PRELOAD=shim, NEXUS_START_FAULT=mode)
    result = subprocess.run([api], env=env, capture_output=True, timeout=10)
    if result.returncode or result.stderr.count(b"proxy-start-fault-injected") != 1:
        raise RuntimeError(f"{mode} API: {result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")
    result = subprocess.run([cli, "run", "38147"], env=env, capture_output=True, timeout=10)
    if result.returncode != 1 or b"cannot initialize proxy:" not in result.stderr or b"proxy-start-fault-injected" not in result.stderr:
        raise RuntimeError(f"{mode} CLI: {result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")
    result = subprocess.run([cli, "run", "--help", "extra"], env=env, capture_output=True, timeout=10)
    if result.returncode != 2 or b"proxy-start-fault-injected" in result.stderr:
        raise RuntimeError(f"{mode} arguments: {result.returncode}, stderr={result.stderr!r}")
env = os.environ.copy()
env.update(LD_PRELOAD=shim, NEXUS_START_FAULT="uring-fallback")
result = subprocess.run([api, "fallback"], env=env, capture_output=True, timeout=10)
if result.returncode or result.stderr.count(b"proxy-start-fault-injected") != 1:
    raise RuntimeError(f"fallback: {result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")
print("ring, eventfd and submit failures recovered; unsupported ring flags fell back")
