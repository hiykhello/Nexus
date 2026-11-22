#!/usr/bin/env python3
"""Real TLS gRPC KeyUpdate, blocked writes and operation lifetime checks."""
import argparse
import pathlib
import subprocess
import tempfile

from grpc_tls_network import certificates

STREAM_MODES = ("key-update", "backpressure", "status", "cancel-send", "cancel-close", "stop-send", "stop-close",
                "exception-read", "exception-write", "abandon-send", "abandon-close")
HANDSHAKE_MODES = ("client-cancel", "server-cancel", "client-stop", "server-stop", "client-exception", "server-exception",
                   "client-abandon", "server-abandon")


def run(binary, mode, root, backend, timeout):
    checked = subprocess.run([binary, mode, root / "cert", root / "key", str(backend)], capture_output=True, timeout=timeout)
    if checked.returncode:
        raise RuntimeError(f"gRPC TLS {mode}, backend={backend}, exit={checked.returncode}: {checked.stdout!r} {checked.stderr!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stress", type=pathlib.Path)
    parser.add_argument("handshake", type=pathlib.Path)
    parser.add_argument("--epoll-only", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nexus-grpc-stress-") as directory:
        root = pathlib.Path(directory)
        certificates(root)
        for backend in ((0,) if args.epoll_only else (0, 1)):
            for mode in STREAM_MODES:
                run(args.stress.resolve(), mode, root, backend, 18)
                print(f"gRPC real TLS stream {mode} passed: backend={backend}", flush=True)
            for mode in HANDSHAKE_MODES:
                run(args.handshake.resolve(), mode, root, backend, 8)
                print(f"gRPC TLS pending handshake {mode} passed: backend={backend}", flush=True)


if __name__ == "__main__":
    main()
