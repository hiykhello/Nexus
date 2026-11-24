#!/usr/bin/env python3
"""Exercise configured proxy chains through the production CLI and fixed sing-box."""
import argparse
import base64
import contextlib
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

def reserve():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise RuntimeError(f"unexpected EOF after {len(result)}/{count} bytes")
        result.extend(part)
    return bytes(result)

def socks(port, command, target):
    client = socket.create_connection(("127.0.0.1", port), timeout=6)
    client.sendall(b"\x05\x01\x00")
    if exact(client, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS negotiation failed")
    client.sendall(bytes([5, command, 0, 1]) + socket.inet_aton(target[0]) + target[1].to_bytes(2, "big"))
    reply = exact(client, 10)
    if reply[:4] != b"\x05\x00\x00\x01":
        raise RuntimeError(f"SOCKS command failed: {reply!r}")
    return client, (socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:10], "big"))

@contextlib.contextmanager
def running(command, port, log):
    with log.open("wb") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 8
            while True:
                if process.poll() is not None:
                    raise RuntimeError(log.read_text())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.02)
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise RuntimeError("process failed to drain")
            if process.returncode:
                raise RuntimeError(f"exit={process.returncode}: {log.read_text()}")


class Dns:
    def __init__(self, delay=0, drops=(), answers=None):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.names = set()
        self.delay = delay
        self.drops = set(drops)
        self.answers = answers or {}
        self.stop = threading.Event()
        self.errors = []
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        try:
            pending = []
            while not self.stop.is_set():
                now = time.monotonic()
                ready = [item for item in pending if item[0] <= now]
                pending = [item for item in pending if item[0] > now]
                for _, answer, peer in ready:
                    self.socket.sendto(answer, peer)
                try:
                    query, peer = self.socket.recvfrom(4096)
                except TimeoutError:
                    continue
                pos, labels = 12, []
                while query[pos]:
                    size = query[pos]
                    labels.append(query[pos + 1:pos + 1 + size].decode())
                    pos += size + 1
                end = pos + 5
                name = ".".join(labels)
                self.names.add(name)
                if name in self.drops:
                    continue
                if query[pos + 1:end] != b"\x00\x01\x00\x01":
                    raise RuntimeError("expected an A query")
                addresses = self.answers.get(name, ("127.0.0.1",))
                answer = query[:2] + b"\x81\x80\x00\x01" + len(addresses).to_bytes(2, "big") + bytes(4) + query[12:end]
                for address in addresses:
                    answer += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(address)
                pending.append((time.monotonic() + self.delay, answer, peer))
        except Exception as error:
            self.errors.append(error)

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.socket.close()
        if self.thread.is_alive() or self.errors:
            raise RuntimeError(f"DNS peer failed: {self.errors}")


def exchange(port):
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        origin.settimeout(8)
        payload = bytes(range(256)) * 1024
        errors = []

        def peer():
            try:
                with origin.accept()[0] as conn:
                    conn.settimeout(8)
                    if exact(conn, len(payload)) != payload or conn.recv(1):
                        raise RuntimeError("upload or half-close mismatch")
                    time.sleep(.05)
                    conn.sendall(payload)
                    conn.shutdown(socket.SHUT_WR)
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=peer)
        thread.start()
        try:
            client, _ = socks(port, 1, origin.getsockname())
            with client:
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                if exact(client, len(payload)) != payload or client.recv(1):
                    raise RuntimeError("download or EOF mismatch")
        finally:
            thread.join(10)
        if thread.is_alive() or errors:
            raise RuntimeError(f"TCP peer failed: {errors}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        origin.bind(("127.0.0.1", 0))
        origin.settimeout(6)
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(6)
        control, relay = socks(port, 3, ("0.0.0.0", 0))
        with control:
            destination = b"\x01\x7f\x00\x00\x01" + origin.getsockname()[1].to_bytes(2, "big")
            for payload in (b"first-session", b"second-datagram"):
                udp.sendto(b"\x00\x00\x00" + destination + payload, relay)
                data, peer = origin.recvfrom(65535)
                if data != payload:
                    raise RuntimeError("UDP upload mismatch")
                origin.sendto(data, peer)
                data, source = udp.recvfrom(65535)
                if source != relay or data != b"\x00\x00\x00" + destination + payload:
                    raise RuntimeError("UDP response address or payload mismatch")


def exchange_http(port):
    for connect in (False, True):
        with socket.socket() as origin:
            origin.bind(("127.0.0.1", 0))
            origin.listen(1)
            origin.settimeout(6)
            errors = []

            def peer():
                try:
                    with origin.accept()[0] as conn:
                        conn.settimeout(6)
                        if connect:
                            if exact(conn, 5) != b"probe" or conn.recv(1):
                                raise RuntimeError("CONNECT pre-read bytes or half-close mismatch")
                            time.sleep(.05)
                            conn.sendall(b"reply")
                        else:
                            request = bytearray()
                            while b"\r\n\r\n" not in request:
                                part = conn.recv(4096)
                                if not part:
                                    raise RuntimeError("truncated forwarded request")
                                request.extend(part)
                            if not request.startswith(b"GET /check HTTP/1.1\r\n"):
                                raise RuntimeError(f"unexpected forwarded request: {request!r}")
                            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nreply")
                        conn.shutdown(socket.SHUT_WR)
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=peer)
            thread.start()
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=6) as client:
                    address = f"127.0.0.1:{origin.getsockname()[1]}"
                    request = f"CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\nprobe" if connect else f"GET http://{address}/check HTTP/1.1\r\nHost: {address}\r\n\r\n"
                    client.sendall(request.encode())
                    client.shutdown(socket.SHUT_WR)
                    response = bytearray()
                    while part := client.recv(4096):
                        response.extend(part)
                    if not response.startswith(b"HTTP/1.1 200 ") or bytes(response).split(b"\r\n\r\n", 1)[1] != b"reply":
                        raise RuntimeError(f"HTTP response mismatch: {response!r}")
            finally:
                thread.join(8)
            if thread.is_alive() or errors:
                raise RuntimeError(f"HTTP peer failed: {errors}")


def configuration(root, ports, chain, port, dns_port, workers, timeouts=()):
    direct_fast = os.getenv("NEXUS_TEST_TFO_DIRECT")
    direct = 'outbound "direct" type="direct" { tcp-fast-open #true; }' if direct_fast else 'outbound "direct" type="direct"'
    text = f'''schema-version 1
role "client"
workers {workers}
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns_port}; strategy "ipv4_only"; }}
inbound "in" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
{direct}
'''
    for index in reversed(range(len(chain))):
        kind = chain[index]
        extra = f'detour "n{index - 1}";' if index else ""
        if not index and direct_fast:
            extra += 'detour "direct";'
        elif not index and kind in ("vless", "vision") and os.getenv("NEXUS_TEST_FAST_OPEN"):
            extra += 'tcp-fast-open #true;'
        if timeouts:
            extra += f'connect-timeout-ms {timeouts[index]};'
        text += f'outbound "n{index}" type="{protocol(kind)}" {{ server host="{kind}.test" port={ports[kind]}; bootstrap-resolver "boot"; {extra} '
        if kind.startswith("ss"):
            text += f'method "2022-blake3-aes-128-gcm"; key-file "{root / "psk"}";'
            if index == len(chain) - 1:
                text += 'udp-over-tcp "v2";'
        elif kind.startswith("trojan"):
            text += f'authentication {{ password-file "{root / "password"}"; }}; tls {{ server-name "cover.example"; ca-file "{root / "cert"}"; verify #true; }};'
        else:
            text += f'authentication {{ uuid-file "{root / "uuid"}"; }}; tls {{ server-name "cover.example"; ca-file "{root / "cert"}"; verify #true; }};'
            if kind == "vision":
                text += 'flow "xtls-rprx-vision";'
        text += "}\n"
    return text + f'routing {{ default-outbound "n{len(chain) - 1}"; }}\n'

def protocol(kind):
    return "shadowsocks" if kind.startswith("ss") else "trojan" if kind.startswith("trojan") else "vless"

def stop_active(port, process):
    with socket.socket() as origin, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        origin.settimeout(4)
        target.bind(("127.0.0.1", 0))
        target.settimeout(4)
        udp.settimeout(4)
        client, _ = socks(port, 1, origin.getsockname())
        with client:
            client.sendall(b"active")
            peer, _ = origin.accept()
            with peer:
                peer.settimeout(3)
                if exact(peer, 6) != b"active":
                    raise RuntimeError("active TCP did not reach origin")
                control, relay = socks(port, 3, ("0.0.0.0", 0))
                with control:
                    packet = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + target.getsockname()[1].to_bytes(2, "big") + b"active"
                    udp.sendto(packet, relay)
                    data, source = target.recvfrom(65535)
                    target.sendto(data, source)
                    if udp.recvfrom(65535)[0] != packet:
                        raise RuntimeError("active UDP response mismatch")
                    process.terminate()
                    process.wait(timeout=2)
                    for stream in (client, control, peer):
                        try:
                            if stream.recv(1):
                                raise RuntimeError("unexpected bytes after stopping")
                        except ConnectionResetError:
                            pass

def tls_failure_cases(binary, root, ports, workers, node="vless"):
    for mode in ("tls-timeout", "tls-stop"):
        dns = Dns(delay=.25 if mode == "tls-timeout" else 0)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(4)
            stalled = {**ports, node: listener.getsockname()[1]}
            port = reserve()
            config = root / "tls-deadline.kdl"
            config.write_text(configuration(root, stalled, ("ss0", node), port, dns.port, workers,
                                            (100, 900 if mode == "tls-timeout" else 5000)))
            errors, accepted = [], threading.Event()

            def peer():
                try:
                    with listener.accept()[0] as conn:
                        conn.settimeout(4)
                        if exact(conn, 1) != b"\x16":
                            raise RuntimeError("expected a TLS ClientHello")
                        accepted.set()
                        while conn.recv(65535):
                            pass
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=peer)
            thread.start()
            try:
                with running([binary, "run", "--config", config], port, root / "tls-deadline.log") as process:
                    with socket.create_connection(("127.0.0.1", port), timeout=4) as client:
                        client.sendall(b"\x05\x01\x00")
                        if exact(client, 2) != b"\x05\x00":
                            raise RuntimeError("TLS deadline negotiation failed")
                        started = time.monotonic()
                        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2")
                        if not accepted.wait(2):
                            raise RuntimeError(f"did not reach TLS peer: {errors}")
                        if mode == "tls-timeout":
                            reply = exact(client, 10)
                            elapsed = time.monotonic() - started
                            if reply[1] != 6 or not .7 <= elapsed < 1.8:
                                raise RuntimeError(f"TLS did not use remaining budget: {reply!r}, {elapsed:.3f}s")
                        else:
                            process.terminate()
                            process.wait(timeout=2)
                            if client.recv(1):
                                raise RuntimeError("TLS stop returned unexpected bytes")
                thread.join(4)
                if thread.is_alive() or errors:
                    raise RuntimeError(f"TLS peer did not drain: {errors}")
                print(f"{workers} workers {node} detour {mode}: passed", flush=True)
            finally:
                dns.close()
                thread.join(5)

def deadline_cases(binary, root, ports, trojan=False):
    for workers in (1, 2):
        for mode in ("shared", "timeout", "stop-tcp", "stop-udp", "stop-data", "candidate"):
            dns = Dns(delay=.25 if mode in ("shared", "timeout") else 0, drops=("ss0.test",) if mode in ("stop-tcp", "stop-udp") else (),
                      answers={"ss0.test": ("127.0.0.2", "127.0.0.1")} if mode == "candidate" else {})
            port = reserve()
            config = root / "deadline.kdl"
            chain = ("ss0", "trojan" if trojan else "vless", "vision") if mode == "stop-data" else ("ss0", "ss1", "ss2")
            config.write_text(configuration(root, ports, chain, port, dns.port, workers,
                                            (100, 100, 2000 if mode in ("shared", "stop-data", "candidate") else 800)))
            try:
                with running([binary, "run", "--config", config], port, root / "deadline.log") as process:
                    if mode in ("shared", "candidate"):
                        exchange(port)
                    elif mode == "stop-data":
                        exchange_http(port)
                        stop_active(port, process)
                    else:
                        client = socket.create_connection(("127.0.0.1", port), timeout=4)
                        with client:
                            client.sendall(b"\x05\x01\x00")
                            if exact(client, 2) != b"\x05\x00":
                                raise RuntimeError("deadline negotiation failed")
                            started = time.monotonic()
                            if mode == "stop-udp":
                                client.sendall(b"\x05\x03\x00\x01" + bytes(6))
                                reply = exact(client, 10)
                                if reply[:4] != b"\x05\x00\x00\x01":
                                    raise RuntimeError("deadline UDP association failed")
                                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                                    udp.sendto(b"\x00\x00\x00\x01\x7f\x00\x00\x01\x04\xd2probe",
                                               (socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:10], "big")))
                            else:
                                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2")
                            if mode == "timeout":
                                reply = exact(client, 10)
                                elapsed = time.monotonic() - started
                                if reply[1] != 6 or not .6 <= elapsed < 1.8 or dns.names != {"ss0.test", "ss1.test", "ss2.test"}:
                                    raise RuntimeError(f"deadline restarted: {reply!r}, {elapsed:.3f}s, {dns.names}")
                            else:
                                limit = time.monotonic() + 2
                                while "ss0.test" not in dns.names:
                                    if time.monotonic() >= limit:
                                        raise RuntimeError(f"did not enter lower bootstrap: {dns.names}")
                                    time.sleep(.01)
                                process.terminate()
                                process.wait(timeout=2)
                                if client.recv(1) or time.monotonic() - started >= 1.8:
                                    raise RuntimeError("detour DNS stop did not drain")
                print(f"{workers} workers detour {mode}: passed", flush=True)
            finally:
                dns.close()
        tls_failure_cases(binary, root, ports, workers)
        if trojan:
            tls_failure_cases(binary, root, ports, workers, "trojan")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--protocol", choices=("all", "ss", "vless", "trojan"), default="all", help="select the enabled feature graph")
    parser.add_argument("--trojan", action="store_true", help="include Trojan in the combined graph")
    args = parser.parse_args()
    binary = args.binary.resolve()
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
    with tempfile.TemporaryDirectory(prefix="nexus-detour-") as directory:
        root = pathlib.Path(directory)
        cert, key, uuid, psk = (root / name for name in ("cert", "key", "uuid", "psk"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                        "-subj", "/CN=cover.example", "-addext", "subjectAltName=DNS:cover.example", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        user = "00010203-0405-0607-0809-0a0b0c0d0e0f"
        password = base64.b64encode(bytes(range(16))).decode()
        uuid.write_text(user)
        psk.write_text(password)
        (root / "password").write_text("trojan-detour-secret\n")
        (root / "password").chmod(0o600)
        uuid.chmod(0o600)
        psk.chmod(0o600)
        kinds = ("ss0", "ss1", "ss2", "vless", "vision")
        if args.trojan or args.protocol == "trojan":
            kinds += ("trojan", "trojan1")
        ports = {kind: reserve() for kind in kinds}
        inbounds = []
        for kind, port in ports.items():
            entry = {"type": protocol(kind), "tag": kind,
                     "listen": "127.0.0.1", "listen_port": port}
            if kind.startswith("ss"):
                entry.update(method="2022-blake3-aes-128-gcm", password=password)
            elif kind.startswith("trojan"):
                entry.update(users=[{"password": "trojan-detour-secret"}],
                             tls={"enabled": True, "certificate_path": str(cert), "key_path": str(key)})
            else:
                entry.update(users=[{"uuid": user, **({"flow": "xtls-rprx-vision"} if kind == "vision" else {})}],
                             tls={"enabled": True, "certificate_path": str(cert), "key_path": str(key)})
            inbounds.append(entry)
        box = root / "box.json"
        box.write_text(json.dumps({"log": {"level": "info", "timestamp": False}, "inbounds": inbounds,
                                  "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}))
        subprocess.run(["sing-box", "check", "-c", box], check=True, capture_output=True)
        log = root / "box.log"
        dns = Dns()
        try:
            with running(["sing-box", "run", "-c", box], ports["ss0"], log):
                chains = [(a, b) for a in ("ss0", "vless", "vision") for b in ("ss1", "vless", "vision") if a != b]
                chains += [("ss0", "ss1", "ss2"), ("ss0", "vless", "ss1"), ("vless", "ss0", "vision")]
                if args.trojan:
                    chains += [(a, b) for a in ("ss0", "vless", "vision", "trojan")
                               for b in ("ss1", "vless", "vision", "trojan") if a != b and "trojan" in (a, b)]
                    chains += [("ss0", "trojan", "vision"), ("trojan", "ss0", "vless"), ("vless", "trojan", "ss1")]
                if args.protocol == "ss":
                    chains = [("ss0", "ss1"), ("ss0", "ss1", "ss2")]
                elif args.protocol == "vless":
                    chains = [("vless", "vision"), ("vision", "vless"), ("vless", "vision", "vless")]
                elif args.protocol == "trojan":
                    chains = [("trojan", "trojan1"), ("trojan", "trojan1", "trojan")]
                for workers in (1, 2):
                    for chain in chains:
                        port = reserve()
                        config = root / "config.kdl"
                        config.write_text(configuration(root, ports, chain, port, dns.port, workers))
                        dns.names.clear()
                        offset = log.stat().st_size
                        with running([binary, "run", "--config", config], port, root / "nexus.log") as process:
                            exchange(port)
                            if args.protocol != "all" and chain == chains[-1]:
                                exchange_http(port)
                                stop_active(port, process)
                        if not {kind + ".test" for kind in chain} <= dns.names:
                            raise RuntimeError(f"missing node bootstrap: {dns.names}")
                        messages = log.read_text()[offset:]
                        for kind in chain:
                            if not any(f"inbound/{protocol(kind)}[{kind}]: " in line and "inbound connection to " in line for line in messages.splitlines()):
                                raise RuntimeError(f"chain skipped {kind}: {messages}")
                        print(f"{workers} workers {' -> '.join(chain)}: TCP, half-close, UDP and drain passed", flush=True)
                if args.protocol == "all":
                    deadline_cases(binary, root, ports, args.trojan)
        finally:
            dns.close()


if __name__ == "__main__":
    main()
