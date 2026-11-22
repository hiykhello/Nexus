"""Exercise fatal and transient epoll accept faults and retry cancellation."""
import os
from pathlib import Path
import subprocess
import sys

worker, transient, retry, shim = (str(Path(arg).resolve()) for arg in sys.argv[1:5])


def run(binary, mode, args, marks):
    env = os.environ.copy()
    env.update(LD_PRELOAD=shim, NEXUS_START_FAULT=mode)
    result = subprocess.run([binary, *args], env=env, capture_output=True, timeout=10)
    if (result.returncode or
            result.stderr.count(b"proxy-start-fault-injected\n") != marks):
        raise RuntimeError(f"{mode} {args}: exit {result.returncode}, "
                           f"stdout={result.stdout!r}, stderr={result.stderr!r}")


for workers in ("1", "2"):
    run(worker, "accept", [workers], 1)
    for mode in ("accept-aborted", "accept-protocol", "accept-netdown", "accept-interrupted"):
        run(transient, mode, [workers], 1)
    run(transient, "accept-burst", [workers], 5)
run(retry, "accept-burst", [], 1)
print("epoll accept failures, transient retries and stop during retry passed")
