#!/usr/bin/env python3
"""HTTPUpgrade TLS post-upgrade controls and operation lifetime checks."""
import argparse
import pathlib
import subprocess
import tempfile

from grpc_tls_network import certificates

MODES = ("key-update", "backpressure", "cancel-send", "cancel-close", "stop-send", "stop-close", "exception-read", "exception-write",
         "abandon-send", "abandon-close", "upgrade-cancel", "upgrade-stop", "upgrade-abandon")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--epoll-only", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nexus-httpupgrade-tls-stress-") as directory:
        root = pathlib.Path(directory)
        certificates(root)
        for backend in ((0,) if args.epoll_only else (0, 1)):
            for mode in MODES:
                checked = subprocess.run([args.fixture.resolve(), mode, root / "cert", root / "key", str(backend)], capture_output=True, timeout=18)
                if checked.returncode:
                    raise RuntimeError(f"HTTPUpgrade TLS {mode}, backend={backend}: exit={checked.returncode}, {checked.stdout!r}, {checked.stderr!r}")
                print(f"HTTPUpgrade TLS {mode} passed: backend={backend}", flush=True)


if __name__ == "__main__":
    main()
