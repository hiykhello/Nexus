#!/usr/bin/env python3
"""Actual joined UDP driver/TLS/QUIC/HTTP3 lifecycle with three credentials."""

import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from tls_raw_quic import credential, run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    report = {"binary": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "expected": 48, "complete": False, "cases": []}
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-quic-driver-lifecycle-") as directory:
            for name, algorithm, options in [
                ("rsa", "RSA", ["-pkeyopt", "rsa_keygen_bits:2048"]),
                ("p256", "EC", ["-pkeyopt", "ec_paramgen_curve:P-256"]),
                ("ed25519", "ED25519", []),
            ]:
                cert, key = credential(Path(directory), name, algorithm, options)
                result = run([binary, cert, key])
                lines = sum(line.startswith("driver native ") for line in result.stdout.splitlines())
                if lines != 16:
                    raise RuntimeError("expected16 native driver lifecycle scenarios")
                report["cases"].append({"algorithm": name, "count": lines, "exit": result.returncode,
                                        "stdout": result.stdout, "stderr": result.stderr})
                print(name + ": " + result.stdout, end="", flush=True)
        report["complete"] = sum(record["count"] for record in report["cases"]) == report["expected"]
    finally:
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
