#!/usr/bin/env python3
"""Steady-state zero-allocation and clean recovery check for UDP driver."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    report = {"binary": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "complete": False, "cases": []}
    try:
        for backend in [0, 1]:
            steady = subprocess.run([str(binary), "--steady", str(backend)],
                                    text=True, capture_output=True, timeout=5)
            report["cases"].append({"backend": backend, "mode": "steady",
                                    "exit": steady.returncode, "stdout": steady.stdout, "stderr": steady.stderr})
            if steady.returncode or "ordinary/array/aligned new=0" not in steady.stdout:
                raise RuntimeError(f"steady driver {backend}: {steady.returncode} {steady.stdout}{steady.stderr}")
            clean = subprocess.run([str(binary), "pmr", "-1", str(backend)],
                                   text=True, capture_output=True, timeout=5)
            report["cases"].append({"backend": backend, "mode": "clean",
                                    "exit": clean.returncode, "stdout": clean.stdout, "stderr": clean.stderr})
            if clean.returncode or "driver process-exit tracked ordinary/array/aligned allocations=0" not in clean.stdout:
                raise RuntimeError(f"clean driver {backend}: {clean.returncode} {clean.stdout}{clean.stderr}")
            print(f"backend={backend}: steady zero-alloc and process-exit leak check passed", flush=True)
        report["complete"] = True
    finally:
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
