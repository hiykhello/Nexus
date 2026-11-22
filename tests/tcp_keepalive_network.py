#!/usr/bin/env python3
"""Check actual production socket options, including detour ownership."""
import argparse
import base64
import json
import pathlib
import re
import secrets
import socket
import subprocess
import tempfile
import threading

from detour_network import Dns, configuration, exact, exchange, running, socks


SETTINGS = "tcp-keepalive #true; tcp-keepalive-idle-seconds 17; tcp-keepalive-interval-seconds 3; tcp-keepalive-count 5;"


def reserve():
    # This driver launches many short-lived clients under strace. Keep listener
    # ports outside the kernel's ephemeral range so a client cannot claim the
    # just-released reservation while the traced server starts.
    ephemeral_start = int(pathlib.Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()[0])
    for _ in range(256):
        port = 1024 + secrets.randbelow(ephemeral_start - 1024)
        with socket.socket() as listener:
            try:
                listener.bind(("127.0.0.1", port))
                listener.listen(1)
            except OSError:
                continue
            return port
    raise RuntimeError("no free test listener port")


def verify(trace, connections, disabled=False, defaults=False):
    lines = [line for line in trace.read_text().splitlines()
             if re.search(r"\b(SO_KEEPALIVE|TCP_KEEPIDLE|TCP_KEEPINTVL|TCP_KEEPCNT)\b", line)]
    expected = [] if defaults else [("SO_KEEPALIVE", 0)] if disabled else [
        ("SO_KEEPALIVE", 1), ("TCP_KEEPIDLE", 17), ("TCP_KEEPINTVL", 3), ("TCP_KEEPCNT", 5)]
    if len(lines) != connections * len(expected):
        raise RuntimeError(f"unexpected socket option count: {lines}")
    for line, (name, value) in zip(lines, expected * connections):
        if not re.search(rf"\b{name}, \[{value}\], 4\)\s+= 0$", line):
            raise RuntimeError(f"option was not applied: {line}")


def launch(binary, config, port, root, fault=()):
    return running(["strace", "-D", "-f", "-qq", "-e", "trace=setsockopt", *fault, "-o", root / "trace",
                    binary, "run", "--config", config], port, root / "nexus.log")


def direct(binary, root, workers, mode):
    port = reserve()
    dns = Dns(answers={"target.test": ("127.0.0.2", "127.0.0.1")})
    fields = "" if mode == "default" else "tcp-keepalive #false;" if mode == "disabled" else SETTINGS
    config = root / "direct.kdl"
    config.write_text(f'''schema-version 1
role "client"
workers {workers}
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.port}; strategy "ipv4_only"; }}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct" {{ {fields} }}
routing {{ default-outbound "direct"; }}
''')
    connections = 0
    try:
        with launch(binary, config, port, root):
            for family in (socket.AF_INET, socket.AF_INET6):
                with socket.socket(family) as origin:
                    origin.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
                    origin.listen(1)
                    origin.settimeout(4)
                    errors = []

                    def peer():
                        try:
                            with origin.accept()[0] as conn:
                                conn.settimeout(4)
                                if exact(conn, 4) != b"ping":
                                    raise RuntimeError("direct payload mismatch")
                                conn.sendall(b"pong")
                        except Exception as error:
                            errors.append(error)

                    thread = threading.Thread(target=peer)
                    thread.start()
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=4) as client:
                            client.sendall(b"\x05\x01\x00")
                            if exact(client, 2) != b"\x05\x00":
                                raise RuntimeError("direct negotiation failed")
                            if family == socket.AF_INET:
                                client.sendall(b"\x05\x01\x00\x03\x0btarget.test" + origin.getsockname()[1].to_bytes(2, "big"))
                                connections += 2
                            else:
                                client.sendall(b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1") + origin.getsockname()[1].to_bytes(2, "big"))
                                connections += 1
                            reply = exact(client, 4)
                            if reply[1] != 0 or reply[3] not in (1, 4):
                                raise RuntimeError("direct connect failed")
                            exact(client, 6 if reply[3] == 1 else 18)
                            client.sendall(b"ping")
                            if exact(client, 4) != b"pong":
                                raise RuntimeError("direct response mismatch")
                    finally:
                        thread.join(5)
                    if thread.is_alive() or errors:
                        raise RuntimeError(f"direct peer failed: {errors}")
        verify(root / "trace", connections, mode == "disabled", mode == "default")
        print(f"{workers} workers direct {mode}: IPv4 candidates, IPv6 and actual socket settings passed", flush=True)
    finally:
        dns.close()


def preparation_failure(binary, root, configured=None, port=None, label="direct"):
    port = port or reserve()
    config = root / "failure.kdl"
    config.write_text(configured or f'''schema-version 1
role "client"
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct" {{ {SETTINGS} }}
routing {{ default-outbound "direct"; }}
''')
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        origin.settimeout(2)
        with launch(binary, config, port, root):
            client, _ = socks(port, 1, origin.getsockname())
            with client, origin.accept()[0]:
                pass
        lines = [line for line in (root / "trace").read_text().splitlines() if "setsockopt(" in line]
        for name in ("SO_KEEPALIVE", "TCP_KEEPIDLE", "TCP_KEEPINTVL", "TCP_KEEPCNT"):
            ordinal = next(index + 1 for index, line in enumerate(lines) if name in line)
            fresh_port = reserve()
            config.write_text(config.read_text().replace(f"port={port};", f"port={fresh_port};"))
            port = fresh_port
            with launch(binary, config, port, root, (f"--inject=setsockopt:error=EPERM:when={ordinal}",)):
                with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                    client.sendall(b"\x05\x01\x00")
                    if exact(client, 2) != b"\x05\x00":
                        raise RuntimeError("failure negotiation failed")
                    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + origin.getsockname()[1].to_bytes(2, "big"))
                    if exact(client, 10)[1] != 1:
                        raise RuntimeError("socket option failure did not fail the request")
                origin.settimeout(.1)
                try:
                    late, _ = origin.accept()
                except TimeoutError:
                    pass
                else:
                    late.close()
                    raise RuntimeError("socket option failure fell back to an unconfigured connect")
                origin.settimeout(2)
                client, _ = socks(port, 1, origin.getsockname())
                with client, origin.accept()[0]:
                    pass
            if not any(name in line and "EPERM" in line and "INJECTED" in line for line in (root / "trace").read_text().splitlines()):
                raise RuntimeError(f"the intended option failure was not injected: {name}")
    print(f"{label} socket option failures refuse connect and preserve later sessions: passed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--protocol", choices=("all", "direct", "ss", "vless"), default="all")
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="nexus-tcp-options-") as directory:
        root = pathlib.Path(directory)
        for workers in (1, 2):
            for mode in ("default", "enabled", "disabled"):
                direct(binary, root, workers, mode)
        preparation_failure(binary, root)
        if args.protocol == "direct":
            return
        revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
        if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
            raise RuntimeError("unexpected sing-box revision")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key", "-out", root / "cert",
                        "-subj", "/CN=cover.example", "-addext", "subjectAltName=DNS:cover.example", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        user = "00010203-0405-0607-0809-0a0b0c0d0e0f"
        password = base64.b64encode(bytes(range(16))).decode()
        for name, value in (("uuid", user), ("psk", password)):
            (root / name).write_text(value)
            (root / name).chmod(0o600)
        ports = {kind: reserve() for kind in ("ss0", "ss1", "vless", "vision")}
        inbounds = []
        for kind, port in ports.items():
            entry = {"type": "shadowsocks" if kind.startswith("ss") else "vless", "tag": kind, "listen": "127.0.0.1", "listen_port": port}
            if kind.startswith("ss"):
                entry.update(method="2022-blake3-aes-128-gcm", password=password)
            else:
                entry.update(users=[{"uuid": user, **({"flow": "xtls-rprx-vision"} if kind == "vision" else {})}],
                             tls={"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")})
            inbounds.append(entry)
        box = root / "box.json"
        box.write_text(json.dumps({"log": {"level": "info"}, "inbounds": inbounds, "outbounds": [{"type": "direct"}]}))
        dns = Dns()
        chains = (("ss0",), ("vless",), ("vision",), ("ss0", "vision"), ("vless", "ss1"), ("ss0", "vless", "ss1"))
        if args.protocol == "ss":
            chains = (("ss0",), ("ss0", "ss1"))
        elif args.protocol == "vless":
            chains = (("vless",), ("vision",), ("vless", "vision"))
        try:
            with running(["sing-box", "run", "-c", box], ports["ss0"], root / "box.log"):
                for workers in (1, 2):
                    for chain in chains:
                        for mode in ("default", "enabled", "disabled", "inherit-direct"):
                            port = reserve()
                            text = configuration(root, ports, chain, port, dns.port, workers)
                            fields = "" if mode == "default" else "tcp-keepalive #false;" if mode == "disabled" else SETTINGS
                            if mode == "inherit-direct":
                                text = text.replace('outbound "direct" type="direct"', f'outbound "direct" type="direct" {{ {fields} }}')
                                fields = 'detour "direct";'
                            text = text.replace(f'server host="{chain[0]}.test"', fields + f' server host="{chain[0]}.test"')
                            config = root / "chain.kdl"
                            config.write_text(text)
                            with launch(binary, config, port, root):
                                exchange(port)
                            verify(root / "trace", 2, mode == "disabled", mode == "default")
                            print(f"{workers} workers {' -> '.join(chain)} {mode}: TCP/UDP and actual socket settings passed", flush=True)
                for chain in chains:
                    port = reserve()
                    text = configuration(root, ports, chain, port, dns.port, 1)
                    text = text.replace(f'server host="{chain[0]}.test"', SETTINGS + f' server host="{chain[0]}.test"')
                    preparation_failure(binary, root, text, port, " -> ".join(chain))
        finally:
            dns.close()


if __name__ == "__main__":
    main()
