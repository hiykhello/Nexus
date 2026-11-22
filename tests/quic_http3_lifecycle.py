#!/usr/bin/env python3
"""Run the real TLS/QUIC/HTTP3 lifecycle matrix with three certificate types."""

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
              "expected": 18, "complete": False, "results": []}
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-http3-lifecycle-") as directory:
            for name, algorithm, options in [
                ("rsa", "RSA", ["-pkeyopt", "rsa_keygen_bits:2048"]),
                ("p256", "EC", ["-pkeyopt", "ec_paramgen_curve:P-256"]),
                ("ed25519", "ED25519", []),
            ]:
                cert, key = credential(Path(directory), name, algorithm, options)
                result = run([binary, cert, key])
                if sum(line.startswith("authenticated QUIC+H3 scenario=") for line in result.stdout.splitlines()) != 6:
                    raise RuntimeError("expected all six real QUIC/HTTP3 lifecycle scenarios")
                print(name + ": " + result.stdout, end="", flush=True)
                report["results"].append({"algorithm": name, "exit": result.returncode,
                                          "scenarios": 6, "stdout": result.stdout, "stderr": result.stderr})
        report["complete"] = sum(result["scenarios"] for result in report["results"]) == report["expected"]
    finally:
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
