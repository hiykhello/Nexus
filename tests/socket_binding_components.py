#!/usr/bin/env python3
"""Run the fixed UDP binding component against real sockets in a private netns."""
import argparse
import hashlib
import json
import pathlib
import selectors
import socket
import subprocess
import sys
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    parser.add_argument("--isolated", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.binary, args.evidence = args.binary.resolve(strict=True), args.evidence.resolve()
    if not args.isolated:
        subprocess.run(["unshare", "-Urn", sys.executable, str(pathlib.Path(__file__).resolve()), str(args.binary),
                        "--evidence", str(args.evidence), "--isolated"], check=True)
        return
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    peers, seen, failures, results = [], [], [], []
    selector, stop = selectors.DefaultSelector(), threading.Event()
    for index, (family, host) in enumerate(((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1"))):
        peer = socket.socket(family, socket.SOCK_DGRAM)
        peer.bind((host, 0))
        peers.append(peer)
        selector.register(peer, selectors.EVENT_READ, index)
    mode = 0

    def echo():
        try:
            while not stop.is_set():
                for key, _ in selector.select(.1):
                    payload, source = key.fileobj.recvfrom(65536)
                    expected = "127.0.0.2" if key.data == 0 and mode & 2 else "127.0.0.1" if key.data == 0 else "::1"
                    if source[0] != expected or payload not in (b"", bytes(range(256))):
                        raise RuntimeError((mode, source, len(payload), expected))
                    seen.append({"family": key.data, "source": source[0], "size": len(payload)})
                    key.fileobj.sendto(payload, source)
        except Exception as error:
            failures.append(str(error))

    thread = threading.Thread(target=echo)
    thread.start()
    complete = False
    try:
        for index, mode in enumerate((0, 1, 2, 4, 6, 8, 15, 16, 31, 32, 38, 47, 64, 0, 128, 0, 256, 0)):
            before = len(seen)
            trace = args.evidence.with_name(f"{args.evidence.stem}-{index}-mode-{mode}.trace")
            command = ["strace", "-f", "-o", str(trace), "-e", "trace=socket,setsockopt,bind,sendto,recvfrom,close",
                       str(args.binary), *(str(peer.getsockname()[1]) for peer in peers), str(mode)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            print(result.stdout, end="", flush=True)
            if result.returncode or len(seen) - before != (0 if mode >= 64 else 4) or failures:
                raise RuntimeError((mode, result.returncode, result.stderr, failures))
            results.append({"mode": mode, "exit": result.returncode, "output": result.stdout, "packets": seen[before:]})
        complete = True
    finally:
        stop.set()
        thread.join(1)
        for peer in peers:
            peer.close()
        selector.close()
        args.evidence.write_text(json.dumps({"complete": complete, "expected_cases": 18, "cases": results,
            "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
            "driver_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()}, indent=2) + "\n")


if __name__ == "__main__":
    main()
