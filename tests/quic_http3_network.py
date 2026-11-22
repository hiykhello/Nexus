#!/usr/bin/env python3
"""Actual HTTP3 auth233 and DATA interop with the fixed quic-go backend."""

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import time

from quic_udp_network import credential, ready


def pair(cpp, go, cert, key, scheme, role, family, mode):
    processes = []
    started = time.monotonic()
    try:
        if role == "client":
            server, port, first = ready([go, "server", family, 0, cert, key])
            processes.append(server)
            client, _, second = ready([cpp, "client", family, port, cert, key, scheme, mode])
        else:
            server, port, first = ready([cpp, "server", family, 0, cert, key, scheme, mode])
            processes.append(server)
            client, _, second = ready([go, "client", family, port, cert, key])
        processes.append(client)
        output, error = client.communicate(timeout=13)
        server_output, server_error = server.communicate(timeout=13)
        record = {"role": role, "family": family, "mode": mode,
                  "client_exit": client.returncode, "server_exit": server.returncode,
                  "client_stdout": second + output, "client_stderr": error,
                  "server_stdout": first + server_output, "server_stderr": server_error,
                  "elapsed": time.monotonic() - started}
        if client.returncode or server.returncode:
            raise RuntimeError(json.dumps(record, indent=2))
        return record
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("peer", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    cpp, go = args.fixture.resolve(), args.peer.resolve()
    report = {"binaries": {str(binary): hashlib.sha256(binary.read_bytes()).hexdigest() for binary in [cpp, go]},
              "expected": 6 if args.quick else 24, "complete": False, "cases": []}
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-http3-udp-") as directory:
            for name, algorithm, options, scheme in [
                ("rsa", "RSA", ["-pkeyopt", "rsa_keygen_bits:2048"], "0x0804"),
                ("p256", "EC", ["-pkeyopt", "ec_paramgen_curve:P-256"], "0x0403"),
                ("ed25519", "ED25519", [], "0x0807"),
            ]:
                cert, key = credential(Path(directory), name, algorithm, options)
                for role in ["client", "server"]:
                    for family in (["4"] if args.quick else ["4", "6"]):
                        for mode in (["normal"] if args.quick else ["normal", "loss"]):
                            record = pair(cpp, go, cert, key, scheme, role, family, mode)
                            record["algorithm"] = name
                            report["cases"].append(record)
                            print(f"{name} Nexus {role} IPv{family} {mode}: HTTP3 auth233/DATA/FIN passed", flush=True)
        report["complete"] = len(report["cases"]) == report["expected"]
    finally:
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
