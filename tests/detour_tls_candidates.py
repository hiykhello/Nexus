#!/usr/bin/env python3
"""Retry a layered TLS node's addresses before sending business requests."""
import argparse
import base64
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

from detour_network import Dns, configuration, exact, exchange, protocol, reserve, running


def candidate(binary, root, ports, chain, workers, mode):
    node = next(kind for kind in reversed(chain) if not kind.startswith("ss"))
    dns = Dns(answers={node + ".test": ("127.0.0.2", "127.0.0.2" if mode == "exhausted" else "127.0.0.1")})
    port = reserve()
    config = root / "config.kdl"
    config.write_text(configuration(root, ports, chain, port, dns.port, workers, (900,) * len(chain)))
    accepted = threading.Event()
    errors = []
    offset = (root / "box.log").stat().st_size
    with socket.socket() as bad:
        bad.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bad.bind(("127.0.0.2", ports[node]))
        if mode != "refused":
            bad.listen(8)
        bad.settimeout(3)

        def peer():
            try:
                # TCP and stream-carried UDP each establish their own chain.
                attempts = 0 if mode == "refused" else 4 if mode == "exhausted" else 2 if mode == "retry" else 1
                for _ in range(attempts):
                    with bad.accept()[0] as conn:
                        conn.settimeout(3)
                        if exact(conn, 1) != b"\x16":
                            raise RuntimeError("bad candidate did not receive a ClientHello")
                        accepted.set()
                        if mode in ("retry", "exhausted"):
                            conn.sendall(b"\x15\x03\x03\x00\x02\x02\x28")
                        else:
                            while conn.recv(65535):
                                pass
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=peer)
        thread.start()
        try:
            with running([binary, "run", "--config", config], port, root / "nexus.log") as process:
                if mode in ("retry", "refused"):
                    exchange(port)
                elif mode == "exhausted":
                    # Exhaustion is local to a request; a later session still
                    # attempts both addresses using a fresh chain.
                    for _ in range(2):
                        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                            client.sendall(b"\x05\x01\x00")
                            if exact(client, 2) != b"\x05\x00":
                                raise RuntimeError("exhaustion negotiation failed")
                            started = time.monotonic()
                            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x09")
                            reply = exact(client, 10)
                            if reply[1] != 4 or time.monotonic() - started > .7:
                                raise RuntimeError(f"exhausted candidates did not fail promptly: {reply!r}")
                else:
                    with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                        client.sendall(b"\x05\x01\x00")
                        if exact(client, 2) != b"\x05\x00":
                            raise RuntimeError("negotiation failed")
                        started = time.monotonic()
                        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x09")
                        if not accepted.wait(2):
                            raise RuntimeError(f"bad candidate was not attempted: {errors}")
                        if mode == "timeout":
                            reply = exact(client, 10)
                            elapsed = time.monotonic() - started
                            if reply[1] != 6 or not .65 <= elapsed < 1.8:
                                raise RuntimeError(f"candidate reset the deadline: {reply!r}, {elapsed:.3f}s")
                        else:
                            process.terminate()
                            process.wait(timeout=2)
                            if client.recv(1):
                                raise RuntimeError("pending candidate survived stop")
            thread.join(4)
            if thread.is_alive() or errors:
                raise RuntimeError(f"candidate peer did not drain: {errors}")
            if not {kind + ".test" for kind in chain} <= dns.names:
                raise RuntimeError(f"missing node bootstrap: {dns.names}")
            if len(chain)>1 and f"inbound connection to 127.0.0.2:{ports[node]}" not in (root / "box.log").read_text()[offset:]:
                raise RuntimeError("the lower node did not attempt the first address")
            print(f"{workers} workers {' -> '.join(chain)} {mode}: passed", flush=True)
        finally:
            dns.close()
            thread.join(4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--mode", choices=("all", "retry", "refused", "exhausted", "timeout", "stop"), default="all")
    parser.add_argument("--protocol", choices=("all", "vless", "trojan"), default="all")
    args = parser.parse_args()
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
    with tempfile.TemporaryDirectory(prefix="nexus-detour-tls-candidates-") as directory:
        root = pathlib.Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key", "-out", root / "cert",
                        "-subj", "/CN=cover.example", "-addext", "subjectAltName=DNS:cover.example", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        user = "00010203-0405-0607-0809-0a0b0c0d0e0f"
        password = base64.b64encode(bytes(range(16))).decode()
        for name, value in (("uuid", user), ("psk", password), ("password", "trojan-detour-secret")):
            (root / name).write_text(value)
            (root / name).chmod(0o600)
        ports = {kind: reserve() for kind in ("ss0", "ss1", "vless", "vision", "trojan")}
        inbounds = []
        for kind, port in ports.items():
            entry = {"type": protocol(kind), "tag": kind,
                     "listen": "127.0.0.1", "listen_port": port}
            if kind.startswith("ss"):
                entry.update(method="2022-blake3-aes-128-gcm", password=password)
            elif kind == "trojan":
                entry.update(users=[{"password": "trojan-detour-secret"}],
                             tls={"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")})
            else:
                entry.update(users=[{"uuid": user, **({"flow": "xtls-rprx-vision"} if kind == "vision" else {})}],
                             tls={"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")})
            inbounds.append(entry)
        box = root / "box.json"
        box.write_text(json.dumps({"log": {"level": "info"}, "inbounds": inbounds, "outbounds": [{"type": "direct"}]}))
        with running(["sing-box", "run", "-c", box], ports["ss0"], root / "box.log"):
            for workers in (1, 2):
                for mode in (("retry", "refused", "exhausted", "timeout", "stop") if args.mode == "all" else (args.mode,)):
                    chains = (("ss0", "vless"), ("ss0", "vision"), ("ss0", "vless", "ss1"), ("vless", "vision"))
                    if args.protocol == "vless":
                        chains = (("vless", "vision"),)
                    elif args.protocol == "trojan":
                        chains = (("trojan",), ("ss0", "trojan"), ("vless", "trojan"), ("ss0", "trojan", "ss1"))
                    for chain in chains:
                        candidate(args.binary.resolve(), root, ports, chain, workers, mode)


if __name__ == "__main__":
    main()
