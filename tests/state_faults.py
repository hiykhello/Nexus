#!/usr/bin/env python3
"""Inject failures at the actual POSIX operations of the snapshot engine."""

import argparse
import errno
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time


def injected(shim, mode, directory):
    env = dict(os.environ, LD_PRELOAD=str(shim), NEXUS_STATE_FAULT=mode)
    env["NEXUS_STATE_DIRECTORY"] = str(directory)
    return env


def run(unit, *args, env=None, status=0):
    result = subprocess.run([unit, *args], env=env, text=True, capture_output=True, timeout=10)
    assert result.returncode == status, result
    return result.stdout.strip()


def crash(unit, shim, directory, phase, expected):
    directory.mkdir(mode=0o700)
    assert run(unit, "write", directory, "1", "old") == "committed"
    env = injected(shim, phase, directory)
    with subprocess.Popen([unit, "write", directory, "2", "new"], stdout=subprocess.PIPE, env=env) as writer:
        try:
            assert select.select([writer.stdout], [], [], 5)[0] and writer.stdout.readline() == b"READY\n", phase
            deadline = time.monotonic() + 5
            while True:
                pid, change = os.waitpid(writer.pid, os.WUNTRACED | os.WNOHANG)
                if pid:
                    assert os.WIFSTOPPED(change), (phase, change)
                    break
                assert time.monotonic() < deadline, phase
                time.sleep(.005)
        finally:
            writer.kill()
            assert writer.wait(timeout=5) == -signal.SIGKILL
    assert run(unit, "read", directory) == expected, phase
    assert run(unit, "write", directory, "3", "after-reopen") == "committed"
    assert run(unit, "read", directory) == "3 after-reopen"
    assert not (directory / ".value.next").exists()
    print(f"PASS SIGKILL {phase}: recovered {expected}; next commit reclaimed staging")


def errors(unit, shim, root):
    uncertain = root / "uncertain"
    uncertain.mkdir(mode=0o700)
    assert run(unit, "write", uncertain, "1", "visible", env=injected(shim, "dir-sync-error", uncertain)) == "uncertain"
    assert run(unit, "read", uncertain) == "1 visible"
    assert run(unit, "write", uncertain, "2", "durable") == "committed"
    cleanup = root / "cleanup"
    cleanup.mkdir(mode=0o700)
    result = run(unit, "write", cleanup, "1", "old", status=3,
                 env=injected(shim, "write-cleanup-error", cleanup))
    assert result == (f"remove staging file os={errno.EACCES} preceding=write file "
                      f"prior-os={errno.EIO} replaced=false"), result
    assert (cleanup / ".value.next").is_file()
    assert run(unit, "write", cleanup, "2", "survives") == "committed"

    snapshot = cleanup / "value.state"
    wire = snapshot.read_bytes()
    damaged = wire[:-1] + bytes([wire[-1] ^ 1])
    snapshot.write_bytes(damaged)
    error = run(unit, "isolate", cleanup, status=3, env=injected(shim, "isolate-error", cleanup))
    assert error == f"isolate damaged file os={errno.EROFS} preceding=checksum mismatch replaced=false", error
    assert snapshot.read_bytes() == damaged and not list(cleanup.glob("*.corrupt.*"))
    print("PASS exact dir-fsync uncertainty, failed unlink errno with original write error, failed isolation")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("unit", type=lambda path: Path(path).resolve(strict=True))
    parser.add_argument("shim", type=lambda path: Path(path).resolve(strict=True))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nexus-state-faults-") as path:
        root = Path(path)
        for phase, expected in [
            ("before-write", "1 old"),
            ("before-rename", "1 old"),
            ("before-dir-sync", "2 new"),
        ]:
            crash(args.unit, args.shim, root / phase, phase, expected)
        errors(args.unit, args.shim, root)
        owner = root / "owner"
        owner.mkdir(mode=0o700)
        print(run(args.unit, "owner", owner, env=injected(args.shim, "hold-stage-sync", owner)))
        visible = root / "visible-owner"
        visible.mkdir(mode=0o700)
        print(run(args.unit, "owner-visible", visible, env=injected(args.shim, "hold-dir-sync", visible)))


if __name__ == "__main__":
    main()
