#!/usr/bin/env python3
"""Trojan CLI against Nexus and pinned sing-box, with actual TCP/UDP targets."""
import argparse
import base64
import contextlib
import hashlib
import json
import pathlib
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

from dns_rule_support import DnsPeer, Echo, connect, exact, free_port, nexus_process, proxy_client, udp_client
from detour_network import running

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=pathlib.Path)
parser.add_argument("--tcp-only", action="store_true")
parser.add_argument("--fast-open", action="store_true")
parser.add_argument("--cross-protocols", action="store_true", help="exercise shared SS/UoT and Trojan inbound forwarding through all protocols")
args = parser.parse_args()
binary = args.binary.resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")


class Origin:
    def __init__(self, ipv6=False, deferred=False):
        self.family = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.host = "::1" if ipv6 else "127.0.0.1"
        self.deferred, self.stop, self.accepted, self.errors = deferred, threading.Event(), [], []
        self.listener = socket.socket(self.family)
        self.listener.bind((self.host, 0))
        self.listener.listen(16)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.workers = []

    def peer(self, client):
        try:
            with client:
                client.settimeout(5)
                data = bytearray()
                while chunk := client.recv(16384):
                    if self.deferred:
                        data.extend(chunk)
                    else:
                        client.sendall(chunk)
                if self.deferred:
                    client.sendall(data)
                client.shutdown(socket.SHUT_WR)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as error:
            self.errors.append(error)

    def serve(self):
        while not self.stop.is_set():
            try:
                client, peer = self.listener.accept()
            except TimeoutError:
                continue
            self.accepted.append(peer)
            worker = threading.Thread(target=self.peer, args=(client,))
            worker.start()
            self.workers.append(worker)

    def __enter__(self):
        self.worker = threading.Thread(target=self.serve)
        self.worker.start()
        return self

    def __exit__(self, kind, *_):
        self.stop.set()
        self.worker.join(2)
        for worker in self.workers:
            worker.join(6)
        self.listener.close()
        if kind is None and self.errors:
            raise self.errors[0]


@contextlib.contextmanager
def sing_server(root, front):
    config = root / "box-server.json"
    config.write_text(json.dumps({"log": {"level": "warn"}, "inbounds": [{"type": "trojan", "listen": "127.0.0.1", "listen_port": front,
        "users": [{"name": "bob", "password": "secret-bob"}],
        "tls": {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")}}],
        "outbounds": [{"type": "direct"}]}))
    process = subprocess.Popen(["sing-box", "run", "-c", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        with connect(front):
            pass
        yield process
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=5)
        if process.returncode:
            raise RuntimeError(f"sing-box server: {stderr!r}")


def outbound(root, front):
    return f'''server host="127.0.0.1" port={front}
 authentication {{ password-file "{root / 'bob'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
 {"tcp-fast-open #true;" if args.fast_open else ""}'''


def socks_stream(front, origin, domain=False):
    with connect(front) as client:
        client.sendall(b"\x05\x01\x00")
        if exact(client, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS greeting")
        address = b"\x03\x0borigin.test" if domain else bytes([1 if origin.family == socket.AF_INET else 4]) + socket.inet_pton(origin.family, origin.host)
        client.sendall(b"\x05\x01\x00" + address + struct.pack("!H", origin.port))
        reply = exact(client, 4)
        if reply[1] or reply[3] not in (1, 4):
            raise RuntimeError(f"Trojan outbound SOCKS reply: {reply!r}")
        exact(client, 6 if reply[3] == 1 else 18)
        payload = bytes(range(256)) * 2048
        errors = []

        def write():
            try:
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
            except Exception as error:
                errors.append(error)

        writer = threading.Thread(target=write)
        writer.start()
        received = exact(client, len(payload))
        if received != payload or client.recv(1):
            raise RuntimeError("Trojan stream data or authenticated half-close")
        writer.join(5)
        if writer.is_alive() or errors:
            raise RuntimeError(f"Trojan stream write: {errors!r}")


def raw_inbound(root, front, origin, password="secret-bob", name="origin.test", accepted=True):
    context = ssl.create_default_context(cafile=str(root / "cert"))
    with connect(front) as raw, context.wrap_socket(raw, server_hostname="localhost") as client:
        key = hashlib.sha224(password.encode()).hexdigest().encode()
        name = name.encode()
        header = key + b"\r\n\x01\x03" + bytes([len(name)]) + name + struct.pack("!H", origin.port) + b"\r\n"
        before = len(origin.accepted)
        # Any fragmentation is legal, including inside the credential itself.
        for offset in range(0, len(header) - 3, 7):
            client.sendall(header[offset:min(offset + 7, len(header) - 3)])
        client.sendall(header[-3:] + b"prefetched")
        if accepted:
            if exact(client, 10) != b"prefetched":
                raise RuntimeError("Trojan inbound lost prefetched bytes")
        else:
            try:
                data = client.recv(1)
            except (ConnectionResetError, ssl.SSLError):
                data = b""
            if data or len(origin.accepted) != before:
                raise RuntimeError("rejected Trojan user reached origin")


def packet_address(host, port):
    if host == "origin.test" or host == "blocked.test":
        raw = host.encode()
        return b"\x03" + bytes([len(raw)]) + raw + struct.pack("!H", port)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    return bytes([4 if family == socket.AF_INET6 else 1]) + socket.inet_pton(family, host) + struct.pack("!H", port)


def packet_reply(client):
    family = exact(client, 1)[0]
    if family not in (1, 3, 4):
        raise RuntimeError(f"invalid Trojan UDP reply family: {family}")
    address = exact(client, exact(client, 1)[0] if family == 3 else 4 if family == 1 else 16)
    port = int.from_bytes(exact(client, 2), "big")
    length = int.from_bytes(exact(client, 2), "big")
    if exact(client, 2) != b"\r\n":
        raise RuntimeError("Trojan UDP reply delimiter")
    return family, address, port, exact(client, length)


def raw_packets(root, front, origin, user="bob", blocked=False, drop_empty=False):
    context = ssl.create_default_context(cafile=str(root / "cert"))
    with connect(front) as raw, context.wrap_socket(raw, server_hostname="localhost") as client:
        key = hashlib.sha224(f"secret-{user}".encode()).hexdigest().encode()
        request = key + b"\r\n\x03" + packet_address("0.0.0.0", 0) + b"\r\n"
        name = "blocked.test" if blocked else "origin.test"
        header = packet_address(name, origin.port)
        payloads = [b"one", b"", bytes(range(256)) * 32, b"last"]
        frames = b"".join(header + struct.pack("!H", len(data)) + b"\r\n" + data for data in payloads)
        for offset in range(0, len(request), 7):
            client.sendall(request[offset:offset + 7])
        # Fragments cross both frame headers and payloads; the final write
        # contains several frames, including an empty datagram.
        client.sendall(frames[:3])
        client.sendall(frames[3:11])
        client.sendall(frames[11:])
        if blocked:
            client.settimeout(.3)
            try:
                client.recv(1)
            except TimeoutError:
                pass
            else:
                raise RuntimeError("rejected Trojan UDP returned data or closed the stream")
            client.settimeout(3)
            payloads = [b"recovery"]
            data = payloads[0]
            client.sendall(packet_address("127.0.0.1", origin.port) + struct.pack("!H", len(data)) + b"\r\n" + data)
        for payload in payloads:
            if not payload and drop_empty:
                continue
            family, _, port, data = packet_reply(client)
            if family not in (1, 4) or port != origin.port or data != payload:
                raise RuntimeError("Trojan UDP address, payload, empty frame or order")
        client.sendall(packet_address("127.0.0.1", origin.port) + b"\x00\x01xx!" )
        try:
            invalid = client.recv(1)
        except (ConnectionResetError, ssl.SSLError):
            invalid = b""
        if invalid:
            raise RuntimeError("malformed Trojan UDP delimiter was forwarded")


def socks_packets(front, origin, drop_empty=False):
    with udp_client(front) as (client, relay):
        for host in ("127.0.0.1", "::1", "origin.test"):
            header = b"\0\0\0" + packet_address(host, origin.port)
            for payload in (b"one", b"", bytes(range(256)) * 32, b"last"):
                if not payload and drop_empty:
                    continue
                client.sendto(header + payload, relay)
                response, _ = client.recvfrom(65535)
                family = response[3]
                if family not in (1, 4):
                    raise RuntimeError("SOCKS/Trojan reply source is not numeric")
                end = 10 if family == 1 else 22
                if int.from_bytes(response[end - 2:end], "big") != origin.port or response[end:] != payload:
                    raise RuntimeError("SOCKS/Trojan UDP frame, source port or payload")


def reject_identity(front, origin):
    before = len(origin.accepted)
    with connect(front) as client:
        client.sendall(b"\x05\x01\x00")
        if exact(client, 2) != b"\x05\x00":
            raise RuntimeError("identity rejection greeting")
        client.sendall(b"\x05\x01\x00" + packet_address(origin.host, origin.port))
        reply = exact(client, 4)
        if not reply[1] or reply[3] not in (1, 4):
            raise RuntimeError(f"invalid TLS identity accepted: {reply!r}")
        exact(client, 6 if reply[3] == 1 else 18)
        if len(origin.accepted) != before:
            raise RuntimeError("TLS identity rejection reached origin")


def cross_protocols(root, workers):
    kinds = ("ss", "vless", "vision", "trojan")
    ports = {kind: free_port() for kind in kinds}
    key, uuid = base64.b64encode(bytes(range(16))).decode(), "00010203-0405-0607-0809-0a0b0c0d0e0f"
    for name, value in (("psk", key), ("uuid", uuid)):
        (root / name).write_text(value)
        (root / name).chmod(0o600)
    inbounds = []
    for kind in kinds:
        entry = {"type": "shadowsocks" if kind == "ss" else "vless" if kind == "vision" else kind,
                 "listen": "127.0.0.1", "listen_port": ports[kind]}
        if kind == "ss":
            entry.update(method="2022-blake3-aes-128-gcm", password=key)
        else:
            entry.update(users=[{"password": "secret-bob"} if kind == "trojan" else {"uuid": uuid, **({"flow": "xtls-rprx-vision"} if kind == "vision" else {})}],
                         tls={"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")})
        inbounds.append(entry)
    box = root / "cross-box.json"
    box.write_text(json.dumps({"log": {"level": "warn"}, "inbounds": inbounds, "outbounds": [{"type": "direct"}]}))
    with running(["sing-box", "run", "-c", box], ports["ss"], root / "cross-box.log"), DnsPeer() as dns, Echo() as origin:
        for kind in kinds:
            front, ss_front = free_port(), free_port()
            if kind == "ss":
                edge = f'''type="shadowsocks" {{ server host="127.0.0.1" port={ports[kind]};
 method "2022-blake3-aes-128-gcm"; key-file "{root / 'psk'}"; udp-over-tcp "v2"; }}'''
            elif kind == "trojan":
                edge = f'type="trojan" {{ {outbound(root, ports[kind])} }}'
            else:
                flow = 'flow "xtls-rprx-vision";' if kind == "vision" else ""
                edge = f'''type="vless" {{ server host="127.0.0.1" port={ports[kind]}; {flow}
 authentication {{ uuid-file "{root / 'uuid'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }} }}'''
            config = root / "cross-server.kdl"
            config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbound "trojan" type="trojan" {{ listen host="127.0.0.1" port={front};
 authentication {{ user "bob" password-file="{root / 'bob'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }} }}
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={ss_front}; method "2022-blake3-aes-128-gcm"; key-file "{root / 'psk'}"; }}
outbound "direct" type="direct"
outbound "edge" {edge}
dns {{ server "remote" type="udp" host="127.0.0.1" port={dns.port}; }}
routing {{ default-outbound "edge"; }}
''')
            with nexus_process(binary, config, 2):
                raw_packets(root, front, origin, drop_empty=kind in ("vless", "vision"))
                client_root = root / f"cross-{workers}-{kind}"
                client_root.mkdir()
                remote = {"type": "shadowsocks", "server": "127.0.0.1", "server_port": ss_front,
                          "method": "2022-blake3-aes-128-gcm", "password": key, "udp_over_tcp": {"enabled": True, "version": 2}}
                with proxy_client(client_root, remote) as socks:
                    socks_packets(socks, origin, drop_empty=kind in ("vless", "vision"))
            print(f"Trojan/SS UoT shared inbound forwarding through {kind}: workers={workers}", flush=True)


def run(root, workers):
    with DnsPeer() as dns, Origin() as live, Origin(deferred=True) as delayed, Origin(ipv6=True, deferred=True) as ipv6, Echo() as packets:
        front = free_port()
        server = root / "server.kdl"
        server.write_text(f'''schema-version 1
role "server"
workers {workers}
inbound "trojan-in" type="trojan" {{
 listen host="127.0.0.1" port={front}
 authentication {{ user "alice" password-file="{root / 'alice'}"; user "bob" password-file="{root / 'bob'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
}}
outbound "direct" type="direct"
dns {{ server "remote" type="udp" host="127.0.0.1" port={dns.port}; rule domain="blocked.test" auth-user="alice" action="reject"; }}
routing {{ default-outbound "direct"; }}
''')
        with nexus_process(binary, server):
            raw_inbound(root, front, live)
            raw_inbound(root, front, live, "wrong", accepted=False)
            raw_inbound(root, front, live, "secret-bob", "blocked.test")
            raw_inbound(root, front, live, "secret-alice", "blocked.test", False)
            if not args.tcp_only:
                raw_packets(root, front, packets)
                raw_packets(root, front, packets, "alice", True)
            remote = {"type": "trojan", "server": "127.0.0.1", "server_port": front, "password": "secret-bob",
                      "tls": {"enabled": True, "server_name": "localhost", "certificate_path": str(root / "cert")}}
            with proxy_client(root, remote) as socks:
                for origin, domain in ((live, False), (delayed, False), (ipv6, False), (live, True)):
                    socks_stream(socks, origin, domain)
                if not args.tcp_only:
                    socks_packets(socks, packets)
            local = root / "client.kdl"
            socks = free_port()
            local.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={socks}; authentication "none"; }}
outbound "direct" type="direct"
outbound "remote" type="trojan" {{ {outbound(root, front)} }}
dns {{ server "remote" type="tcp" host="127.0.0.1" port={dns.port}; }}
routing {{ default-outbound "remote"; }}
''')
            with nexus_process(binary, local):
                for origin, domain in ((live, False), (delayed, False), (ipv6, False), (live, True)):
                    socks_stream(socks, origin, domain)
                if not args.tcp_only:
                    socks_packets(socks, packets)
            valid = local.read_text()
            for original, replacement in (('server-name "localhost"', 'server-name "wrong.example"'),
                                           (str(root / "cert"), str(root / "untrusted-cert"))):
                rejected_socks = free_port()
                local.write_text(valid.replace(original, replacement).replace(f'port={socks}; authentication', f'port={rejected_socks}; authentication'))
                with nexus_process(binary, local):
                    reject_identity(rejected_socks, live)
            local.write_text(valid)
        box_front,box_socks=free_port(),free_port()
        local.write_text(local.read_text().replace(f'server host="127.0.0.1" port={front}',f'server host="127.0.0.1" port={box_front}')
                         .replace(f'listen host="127.0.0.1" port={socks}',f'listen host="127.0.0.1" port={box_socks}'))
        with sing_server(root, box_front):
            with nexus_process(binary, local):
                for origin, domain in ((live, False), (delayed, False), (ipv6, False)):
                    socks_stream(box_socks, origin, domain)
                if not args.tcp_only:
                    socks_packets(box_socks, packets)
        print(f"Trojan {'TCP' if args.tcp_only else 'TCP/UDP'} client/server, TLS, domain/dual-stack, credentials, framing and half-close passed: workers={workers}", flush=True)


with tempfile.TemporaryDirectory(prefix="nexus-trojan-network-") as directory:
    root = pathlib.Path(directory)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "key"),
                    "-out", str(root / "cert"), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root / "key").chmod(0o600)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "untrusted-key"),
                    "-out", str(root / "untrusted-cert"), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for user in ("alice", "bob"):
        (root / user).write_text(f"secret-{user}\n")
        (root / user).chmod(0o600)
    for workers in (1, 2):
        run(root, workers)
        if args.cross_protocols:
            cross_protocols(root, workers)
