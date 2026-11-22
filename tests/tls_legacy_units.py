#!/usr/bin/env python3
"""Run the existing no-argument TLS targets from an explicitly selected build."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


CASES = """
tls-record tls-schedule tls-transcript tls-client-auth tls-application-io
tls-corosio-connection tls-application-close tls-certificate-trust
tls-certificate-verify tls-client-flight tls-client-hello-stream tls-client-keys
tls-corosio-application tls-corosio-application-input tls-corosio-handshake
tls-encrypted-extensions tls-finished tls-handshake tls-hello tls-hello-integration
tls-hybrid tls-hybrid-client-keys tls-key-share tls-key-update tls-record-stream
tls-server-hello tls-server-hello-stream tls-server-keys tls-ticket tls-owned-prefix
""".split()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    directory = args.directory.resolve(strict=True)
    binaries = {name: directory / name for name in CASES}
    for binary in binaries.values():
        if not binary.is_file():
            parser.error(f"missing selected TLS target: {binary}")
    selected = directory / "sha256.json"
    hashes = json.loads(selected.read_text()) if selected.is_file() else {}
    results, complete = [], False
    try:
        for name, binary in binaries.items():
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            if hashes and hashes.get(name) != digest:
                raise RuntimeError(f"selected artifact SHA256 mismatch: {name}")
            result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=90)
            record = {"name": name, "exit": result.returncode, "sha256": digest,
                      "stdout": result.stdout, "stderr": result.stderr}
            results.append(record)
            print(f"{name}: exit {result.returncode}\n{result.stdout}{result.stderr}", end="", flush=True)
            if result.returncode:
                raise RuntimeError(f"{name} failed with exit {result.returncode}")
        complete = True
    finally:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps({"complete": complete, "expected": len(CASES),
            "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "cases": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
