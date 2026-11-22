#!/usr/bin/env python3
"""Real TLS/QUIC/H3 over the production UDP driver on both native backends."""

import argparse
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import threading
import time

from quic_udp_network import credential, ready


def pair(cpp, go, cert, key, scheme, role, family, backend, loss):
    processes = []
    stop = threading.Event()
    proxy = None
    thread = None
    dropped = forwarded = 0
    started = time.monotonic()
    try:
        if role == "client":
            server, port, first = ready([go, "server", family, 0, cert, key])
        else:
            server, port, first = ready([cpp, "server", family, 0, cert, key, scheme, backend])
        processes.append(server)
        destination = port
        if loss:
            host, af = ("::1", socket.AF_INET6) if family == "6" else ("127.0.0.1", socket.AF_INET)
            proxy = socket.socket(af, socket.SOCK_DGRAM)
            proxy.bind((host, 0))
            proxy.settimeout(.01)
            destination = proxy.getsockname()[1]

            def forward():
                nonlocal dropped, forwarded
                client_address = None
                while not stop.is_set():
                    try:
                        data, source = proxy.recvfrom(65535)
                    except socket.timeout:
                        continue
                    from_server = source[1] == port
                    if not from_server:
                        client_address = source
                    target = client_address if from_server else (host, port)
                    if target is None:
                        raise RuntimeError("server sent before client path discovery")
                    # One actual post-handshake short-header QUIC datagram
                    # has already completed the Nexus socket send operation.
                    if not dropped and data and not data[0] & 0x80 and from_server == (role == "server"):
                        dropped += 1
                        continue
                    proxy.sendto(data, target)
                    forwarded += 1

            thread = threading.Thread(target=forward)
            thread.start()
        if role == "client":
            client, _, second = ready([cpp, "client", family, destination, cert, key, scheme, backend])
        else:
            client, _, second = ready([go, "client", family, destination, cert, key])
        processes.append(client)
        output, error = client.communicate(timeout=13)
        server_output, server_error = server.communicate(timeout=13)
        record = {"role": role, "family": family, "backend": backend, "loss": loss,
                  "client_exit": client.returncode, "server_exit": server.returncode,
                  "client_stdout": second + output, "client_stderr": error,
                  "server_stdout": first + server_output, "server_stderr": server_error,
                  "dropped": dropped, "forwarded": forwarded, "elapsed": time.monotonic() - started}
        if client.returncode or server.returncode or loss and dropped != 1:
            raise RuntimeError(json.dumps(record, indent=2))
        return record
    finally:
        stop.set()
        if thread:
            thread.join(timeout=1)
        if proxy:
            proxy.close()
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
              "expected": 6 if args.quick else 48, "complete": False, "cases": []}
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-h3-datagram-") as directory:
            for name, algorithm, options, scheme in [
                ("rsa", "RSA", ["-pkeyopt", "rsa_keygen_bits:2048"], "0x0804"),
                ("p256", "EC", ["-pkeyopt", "ec_paramgen_curve:P-256"], "0x0403"),
                ("ed25519", "ED25519", [], "0x0807"),
            ]:
                cert, key = credential(Path(directory), name, algorithm, options)
                for role in ["client", "server"]:
                    for family in (["4"] if args.quick else ["4", "6"]):
                        for backend in (["0"] if args.quick else ["0", "1"]):
                            for loss in ([False] if args.quick else [False, True]):
                                record = pair(cpp, go, cert, key, scheme, role, family, backend, loss)
                                record["algorithm"] = name
                                report["cases"].append(record)
                                print(f"{name} Nexus {role} IPv{family} backend={backend} loss={loss}: real driver auth233/DATA/ACK/drain passed", flush=True)
        report["complete"] = len(report["cases"]) == report["expected"]
    finally:
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
