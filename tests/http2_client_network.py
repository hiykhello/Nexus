#!/usr/bin/env python3
"""Check the bounded H2 driver against a pinned independent Go H2 server."""
import argparse
import hashlib
import json
import pathlib
import select
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--peer", type=pathlib.Path, required=True)
    parser.add_argument("--epoll-only", action="store_true")
    parser.add_argument("--evidence", type=pathlib.Path)
    args = parser.parse_args()
    binary, peer = args.binary.resolve(), args.peer.resolve()
    checked = {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
               "peer_sha256": hashlib.sha256(peer.read_bytes()).hexdigest(), "results": []}
    server = subprocess.Popen([peer], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if not select.select([server.stdout], [], [], 5)[0]:
            raise RuntimeError("H2 peer did not report its listener")
        port = server.stdout.readline().strip()
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise RuntimeError(f"invalid H2 peer listener: {port!r}")
        for backend in ((0,) if args.epoll_only else (0, 1)):
            started = time.monotonic()
            result = subprocess.run([binary, port, str(backend)], capture_output=True, text=True, timeout=20)
            checked["results"].append({"backend": backend, "exit_code": result.returncode,
                                       "stdout": result.stdout, "stderr": result.stderr,
                                       "seconds": round(time.monotonic() - started, 3)})
            if args.evidence:
                args.evidence.write_text(json.dumps(checked, indent=2) + "\n")
            if result.returncode:
                raise RuntimeError(f"H2 driver backend={backend}, exit={result.returncode}: {result.stdout!r} {result.stderr!r}")
            print(result.stdout, end="", flush=True)
    finally:
        if server.poll() is None:
            server.terminate()
        _, stderr = server.communicate(timeout=5)
        if stderr:
            raise RuntimeError(f"H2 reference server failed: {stderr!r}")


if __name__ == "__main__":
    main()
