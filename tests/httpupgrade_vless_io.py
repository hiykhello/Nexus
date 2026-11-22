#!/usr/bin/env python3
"""Exercise upgraded production VLESS TLS types under controls and cancellation."""
import argparse
import pathlib
import subprocess

MODES = ("key-update", "backpressure", "cancel", "stop", "abandon", "exception-read", "exception-write",
         "upgrade-cancel", "upgrade-stop", "upgrade-abandon")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--epoll-only", action="store_true")
    args = parser.parse_args()
    for backend in ((0,) if args.epoll_only else (0, 1)):
        for role in ("client", "server"):
            for mode in MODES:
                checked = subprocess.run([args.fixture.resolve(), mode, role, str(backend)], capture_output=True, timeout=9)
                if checked.returncode:
                    raise RuntimeError(f"production VLESS/Upgrade {mode} {role}, backend={backend}: {checked.returncode}, {checked.stdout!r}, {checked.stderr!r}")
                print(f"production VLESS/Upgrade {mode} {role} passed: backend={backend}", flush=True)


if __name__ == "__main__":
    main()
