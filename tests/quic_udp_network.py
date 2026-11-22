#!/usr/bin/env python3
"""Authenticated UDP transport interop with the fixed sing-quic QUIC backend."""

import argparse
import hashlib
import json
from pathlib import Path
import selectors
import socket
import subprocess
import tempfile
import threading
import time


def run(command):
    result = subprocess.run([str(value) for value in command], text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError(f"command exited {result.returncode}: {result.stdout}{result.stderr}")
    return result


def credential(root, name, algorithm, options):
    key, cert = root / (name + ".pem"), root / (name + "-cert.der")
    key_der = root / (name + "-key.der")
    run(["openssl", "genpkey", "-algorithm", algorithm, *options, "-out", key])
    run(["openssl", "pkey", "-in", key, "-outform", "DER", "-out", key_der])
    run(["openssl", "req", "-new", "-x509", "-key", key, "-days", "1", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost", "-outform", "DER", "-out", cert])
    return cert, key_der


def ready(command):
    process = subprocess.Popen([str(value) for value in command], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        if not selector.select(10):
            raise RuntimeError("fixture readiness timeout")
        line = process.stdout.readline()
        if not line.startswith("READY "):
            raise RuntimeError(f"fixture failed before ready: {line} {process.stderr.read()}")
        return process, int(line.split()[1]), line
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()


def pair(cpp, go, cert, key, scheme, role, family, curve, mode="normal", wrong=None, cipher=None):
    processes = []
    cpp_cert, name = (wrong, "localhost") if mode == "wrong-ca" else (cert, "wrong.example") if mode == "wrong-name" else (cert, "localhost")
    cpp_mode = "reject" if mode.startswith("wrong-") else mode
    go_mode = "reject" if mode.startswith("wrong-") else mode
    started = time.monotonic()
    try:
        if role == "client":
            server, port, first = ready([go, "server", family, 0, cert, key, "localhost", go_mode, curve])
            processes.append(server)
            command = [cpp, "client", family, port, cpp_cert, key, scheme, curve, cpp_mode, name]
            client, _, second = ready(command + ([cipher] if cipher else []))
        else:
            server, port, first = ready([cpp, "server", family, 0, cert, key, scheme, curve, cpp_mode, "localhost"])
            processes.append(server)
            client, _, second = ready([go, "client", family, port, cpp_cert, key, name, go_mode, curve])
        processes.append(client)
        out, err = client.communicate(timeout=13)
        server_out, server_err = server.communicate(timeout=13)
        evidence = {"role": role, "family": family, "curve": curve, "mode": mode, "cipher": cipher,
                    "client_exit": client.returncode, "server_exit": server.returncode,
                    "client_stdout": second + out, "client_stderr": err,
                    "server_stdout": first + server_out, "server_stderr": server_err,
                    "elapsed": time.monotonic() - started}
        if client.returncode or server.returncode:
            raise RuntimeError(json.dumps(evidence, indent=2))
        if cipher and f"cipher={cipher}" not in server_out:
            raise RuntimeError(f"Go peer did not report expected TLS cipher {cipher}")
        return evidence
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()


def deadline_case(cpp, go, cert, key, scheme, family, server):
    host, af = ("::1", socket.AF_INET6) if family == "6" else ("127.0.0.1", socket.AF_INET)
    stop = threading.Event()
    client = None
    forwards = drops = 0
    with socket.socket(af, socket.SOCK_DGRAM) as proxy:
        proxy.bind((host, 0))
        started = time.monotonic()
        fixture, port, prefix = ready([cpp, "server" if server else "client", family,
                                      0 if server else proxy.getsockname()[1], cert, key, scheme,
                                      "x", "timeout", "localhost"])
        def blackhole():
            nonlocal forwards, drops
            proxy.settimeout(.01)
            first, repeated = None, 0
            while not stop.is_set():
                try:
                    data, source = proxy.recvfrom(65535)
                    if source[1] == port:
                        drops += 1
                    else:
                        first = data
                        proxy.sendto(data, (host, port))
                        forwards += 1
                except socket.timeout:
                    pass
                if first is not None and time.monotonic() - repeated >= .04:
                    proxy.sendto(first, (host, port))
                    forwards += 1
                    repeated = time.monotonic()
        thread = threading.Thread(target=blackhole)
        try:
            if server:
                thread.start()
                # The original 1.2s budget already runs before a valid TLS CH
                # arrives. Duplicate valid Initials then keep the socket active.
                time.sleep(.7)
                client, _, _ = ready([go, "client", family, proxy.getsockname()[1], cert, key,
                                      "localhost", "stop", "x"])
            output, error = fixture.communicate(timeout=3)
            elapsed = time.monotonic() - started
            if fixture.returncode or "started=true authenticated=0" not in output or "failure=0" not in output or not 1.15 <= elapsed <= 1.5:
                raise RuntimeError(f"absolute deadline: exit={fixture.returncode} elapsed={elapsed} {output}{error}")
            if client:
                client_out, client_error = client.communicate(timeout=3)
                if client.returncode or forwards < 3 or drops == 0:
                    raise RuntimeError(f"late TLS fixture failed: forwarded={forwards} dropped={drops} {client_out}{client_error}")
            return {"role": "server" if server else "client", "family": family, "mode": "absolute-deadline",
                    "exit": fixture.returncode, "elapsed": elapsed, "forwarded": forwards, "dropped": drops,
                    "stdout": prefix + output, "stderr": error}
        finally:
            stop.set()
            if server:
                thread.join(timeout=1)
            for process in [fixture, client]:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("peer", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    cpp, go = args.fixture.resolve(), args.peer.resolve()
    records = []
    with tempfile.TemporaryDirectory(prefix="nexus-quic-udp-") as directory:
        root = Path(directory)
        wrong, _ = credential(root, "wrong", "ED25519", [])
        for name, algorithm, options, scheme in [
            ("rsa", "RSA", ["-pkeyopt", "rsa_keygen_bits:2048"], "0x0804"),
            ("p256", "EC", ["-pkeyopt", "ec_paramgen_curve:P-256"], "0x0403"),
            ("ed25519", "ED25519", [], "0x0807"),
        ]:
            cert, key = credential(root, name, algorithm, options)
            cases = [("client", "4", "x", "normal"), ("server", "4", "x", "normal")]
            if not args.quick:
                cases = [(role, family, curve, "normal") for role in ["client", "server"]
                         for family in ["4", "6"] for curve in ["x", "hybrid", "retry"]]
            for role, family, curve, mode in cases:
                evidence = pair(cpp, go, cert, key, scheme, role, family, curve, mode, wrong)
                evidence["algorithm"] = name
                records.append(evidence)
                print(f"{name} Nexus {role} IPv{family} {curve} {mode}: authenticated transport passed", flush=True)
            if not args.quick:
                for family in ["4", "6"]:
                    for curve in ["x", "hybrid", "retry"]:
                        evidence = pair(cpp, go, cert, key, scheme, "client", family, curve, cipher="0x1302")
                        evidence["algorithm"] = name
                        records.append(evidence)
                        print(f"{name} Nexus client IPv{family} {curve} AES256: passed", flush=True)
                for role in ["client", "server"]:
                    for mode in ["loss", "wrong-name", "wrong-ca", "stop"]:
                        evidence = pair(cpp, go, cert, key, scheme, role, "4", "x", mode, wrong)
                        evidence["algorithm"] = name
                        records.append(evidence)
                        print(f"{name} Nexus {role} {mode}: passed", flush=True)
        if not args.quick:
            for family in ["4", "6"]:
                for server in [False, True]:
                    evidence = deadline_case(cpp, go, cert, key, scheme, family, server)
                    records.append(evidence)
                    print(f"Nexus {evidence['role']} IPv{family} absolute 1.2s deadline: passed", flush=True)
    if args.report:
        args.report.write_text(json.dumps({"binaries": {str(binary): hashlib.sha256(binary.read_bytes()).hexdigest()
                                                      for binary in [cpp, go]}, "cases": records}, indent=2) + "\n")


if __name__ == "__main__":
    main()
