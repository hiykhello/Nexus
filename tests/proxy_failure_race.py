"""Verify two concurrent accept failures retain the published error through stop."""
import os
from pathlib import Path
import subprocess
import sys

binary, shim = (str(Path(arg).resolve()) for arg in sys.argv[1:3])
env = os.environ.copy()
env.update(LD_PRELOAD=shim, NEXUS_START_FAULT="accept-race")
for i in range(20):
    result = subprocess.run([binary, "race"], env=env, capture_output=True, timeout=10)
    if result.returncode or result.stderr.count(b"proxy-start-fault-injected\n") != 2 or b"proxy-fault-barrier-timeout" in result.stderr:
        raise RuntimeError(f"iteration {i}: exit={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")
print("20 two-worker failure races retained the published error, recovered resources and restarted")
