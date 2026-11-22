#!/usr/bin/env python3
"""Run shared raw TLS and authenticated QUIC tests with three real key types."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def run(command, timeout=120):
    result = subprocess.run([str(part) for part in command], text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}: {result.stdout}{result.stderr}")
    return result


def credential(root, name, algorithm, options):
    key = root / (name + ".pem")
    key_der, cert = root / (name + "-key.der"), root / (name + "-cert.der")
    run(["openssl", "genpkey", "-algorithm", algorithm, *options, "-out", key])
    run(["openssl", "pkey", "-in", key, "-outform", "DER", "-out", key_der])
    run(["openssl", "req", "-new", "-x509", "-key", key, "-days", "1",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
         "-outform", "DER", "-out", cert])
    return cert, key_der


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-bin", type=Path)
    parser.add_argument("--quic-bin", type=Path)
    parser.add_argument("--wrapped-records", action="store_true")
    parser.add_argument("--faults", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not args.raw_bin and not args.quic_bin:
        parser.error("provide --raw-bin or --quic-bin")
    if (args.wrapped_records or args.faults) and not args.quic_bin:
        parser.error("--wrapped-records and --faults require --quic-bin")
    records = []
    with tempfile.TemporaryDirectory(prefix="nexus-raw-quic-") as directory:
        root = Path(directory)
        wrong, _ = credential(root, "wrong", "ED25519", [])
        for name, algorithm, options in [
            ("rsa", "RSA", ["-pkeyopt", "rsa_keygen_bits:2048"]),
            ("p256", "EC", ["-pkeyopt", "ec_paramgen_curve:P-256"]),
            ("ed25519", "ED25519", []),
        ]:
            cert, key = credential(root, name, algorithm, options)
            for kind, binary in [("raw", args.raw_bin), ("quic", args.quic_bin)]:
                if binary is None:
                    continue
                binary = binary.resolve()
                command = [binary, cert, key]
                if kind == "quic":
                    command += [wrong]
                    if args.wrapped_records:
                        command += ["--wrapped-records"]
                    if args.faults:
                        command += ["--faults"]
                result = run(command)
                print(f"{name}/{kind}: {result.stdout.strip()}", flush=True)
                records.append({"algorithm": name, "kind": kind, "exit": result.returncode,
                                "binary": str(binary),
                                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                                "stdout": result.stdout, "stderr": result.stderr,
                                "wrapped_records": kind == "quic" and args.wrapped_records,
                                "faults": kind == "quic" and args.faults})
    if args.report:
        args.report.write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
