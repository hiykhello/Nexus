"""Observe per-context resolver pool concurrency using a gated getaddrinfo."""
import os
import select
import subprocess
import sys
import time
from pathlib import Path

binary, shim = (str(Path(value).resolve()) for value in sys.argv[1:3])


def run(size):
    ready_r, ready_w = os.pipe()
    gate_r, gate_w = os.pipe()
    env = os.environ.copy()
    env.update(LD_PRELOAD=shim, NEXUS_TEST_RESOLVER_READY_FD=str(ready_w),
               NEXUS_TEST_RESOLVER_GATE_FD=str(gate_r))
    process = subprocess.Popen([binary, str(size)], env=env, pass_fds=(ready_w, gate_r))
    os.close(ready_w)
    os.close(gate_r)
    try:
        batch = 3 * size
        observed = 0
        deadline = time.monotonic() + 3
        while observed < batch:
            if not select.select([ready_r], [], [], max(0, deadline - time.monotonic()))[0]:
                raise RuntimeError(f"pool {size}: only {observed}/{batch} queries entered")
            observed += len(os.read(ready_r, batch - observed))
        if select.select([ready_r], [], [], 0.15)[0]:
            raise RuntimeError(f"pool {size}: more than {batch} simultaneous calls")
        # Later work may consume permits unevenly; do not assume pool fairness.
        os.write(gate_w, b"x" * 9)
        if process.wait(timeout=3):
            raise RuntimeError(f"pool {size}: client exit {process.returncode}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(ready_r)
        os.close(gate_w)


run(1)
run(2)
print("three Corosio contexts use independent bounded resolver worker pools")
