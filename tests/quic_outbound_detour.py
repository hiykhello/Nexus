#!/usr/bin/env python3
"""Exercise TUIC and MASQUE CONNECT-UDP across named datagram detours."""
from contextlib import contextmanager
import base64
import json
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from detour_network import running
from dns_rule_support import DnsPeer, Echo, free_port, nexus_process, stream_request, udp_client
from named_http3_detour import private_file, trojan_listener
from tuic_singbox import REVISION, socks5_tcp_echo, stop_proc
from udp_bind_port_network import certificate


class UdpObserver:
    def __init__(self, port):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.remote = ("127.0.0.1", port)
        self.sources = set()
        self.stop = threading.Event()
        self.errors = []

    def forward(self):
        client = None
        self.udp.settimeout(.05)
        while not self.stop.is_set():
            try:
                data, sender = self.udp.recvfrom(65535)
                if sender == self.remote:
                    if client:
                        self.udp.sendto(data, client)
                else:
                    client = sender
                    self.sources.add(sender)
                    self.udp.sendto(data, self.remote)
            except TimeoutError:
                continue
            except OSError as error:
                self.errors.append(error)
                return

    def __enter__(self):
        self.thread = threading.Thread(target=self.forward)
        self.thread.start()
        return self

    def __exit__(self, kind, *_):
        self.stop.set()
        self.thread.join(2)
        self.udp.close()
        if not kind and (self.errors or self.thread.is_alive()):
            raise RuntimeError(f"QUIC relay failed to drain: {self.errors!r}")


class Fixture:
    def __init__(self, root, binary, dns):
        self.root, self.binary, self.dns = root, binary, dns
        self.file = root / "client.kdl"
        certificate(root)
        self.secret = private_file(root, "password", "detour-password")
        self.uuid = private_file(root, "uuid", "b7c2f3e8-1d44-4a5b-9e6c-0a1b2c3d4e5f")
        self.key = private_file(root, "sskey", base64.b64encode(bytes(range(16))).decode())
        self.token = private_file(root, "bearer", "approved")
        self.bad_token = private_file(root, "wrong", "denied")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.2", 0))
            self.source_port = reserve.getsockname()[1]
        self.tls = f'tls {{ server-name "localhost"; ca-file "{root / "cert"}"; verify #true; }}'

    def trojan(self, port):
        return f'''outbound "lower" type="trojan" {{
  server host="lower.test" port={port}; bootstrap-resolver "test"; detour "physical";
  authentication {{ password-file "{self.secret}"; }}; {self.tls};
}}'''

    def ss(self, port, uot=True):
        option = 'udp-over-tcp "v2";' if uot else ""
        return f'''outbound "lower" type="shadowsocks" {{
  server host="lower.test" port={port}; bootstrap-resolver "test"; detour "physical";
  method "2022-blake3-aes-128-gcm"; key-file "{self.key}"; {option}
}}'''

    def configure(self, protocol, port, detour="lower", lower="", udp_stream=False, timeout=1700, token=None, extra=""):
        self.front = free_port()
        if protocol == "tuic":
            auth = f'''uuid-file "{self.uuid}"; password-file "{self.secret}";'''
            fields = 'udp-over-stream #true;' if udp_stream else ""
        else:
            auth = f'bearer-file "{token or self.token}";'
            fields = 'authority "localhost";'
        self.file.write_text(f'''schema-version 1
role "client"
inbound "front" type="socks5" {{ listen host="127.0.0.1" port={self.front}; authentication "none"; }}
outbound "physical" type="direct" {{ inet4-bind-address "127.0.0.2"; udp-bind-port {self.source_port}; }}
{lower}
outbound "edge" type="{protocol}" {{
  server host="quic.test" port={port}; bootstrap-resolver "test"; detour "{detour}";
  authentication {{ {auth} }}; {self.tls};
  connect-timeout-ms {timeout}; {fields} {extra}
}}
dns {{ server "test" type="udp" host="127.0.0.1" port={self.dns.port}; final "test"; strategy "ipv4_only"; }}
routing {{
  tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{
    rule action="route" outbound="edge"
  }}
  final "edge"
}}
''')
        return self.file


@contextmanager
def masque_peer(root, binary):
    command = [binary, "serve-detour", root / "cert", root / "key"]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as peer:
        try:
            if not select.select([peer.stdout], [], [], 5)[0]:
                raise RuntimeError("CONNECT-UDP peer did not start")
            port = int(peer.stdout.readline().rsplit(b":", 1)[1])
            yield peer, port
        finally:
            stop_proc(peer)


def packet(client, relay, port, data, success=True):
    frame = b"\0\0\0\1\x7f\0\0\1" + port.to_bytes(2, "big")
    client.sendto(frame + data, relay)
    client.settimeout(4 if success else .45)
    try:
        reply = client.recv(65535)
    except TimeoutError:
        if success:
            raise
        return
    if not success or reply != frame + data:
        raise RuntimeError(f"unexpected routed UDP response: {reply[:24]!r}")


def check_masque(f, peer_binary, trojan_port, ss_port):
    cases = (
        ("physical", "", "127.0.0.2", f.source_port),
        ("lower", f.trojan(trojan_port), "127.0.0.3", None),
        ("lower", f.ss(ss_port), "127.0.0.4", None),
    )
    for detour, lower, host, expected_port in cases:
        with masque_peer(f.root, peer_binary) as (peer, port):
            config = f.configure("masque", port, detour, lower)
            with nexus_process(f.binary, config), udp_client(f.front) as (client, relay):
                for payload in (b"masque", b"", b"m" * 1024):
                    packet(client, relay, 53, payload)
                if not select.select([peer.stdout], [], [], 2)[0]:
                    raise RuntimeError("peer did not record the CONNECT-UDP request")
                observed_host, observed_port = peer.stdout.readline().decode().strip().rsplit(":", 1)
                if observed_host != host or (expected_port and int(observed_port) != expected_port):
                    raise RuntimeError(f"wrong CONNECT-UDP egress {observed_host}:{observed_port}")
            config = f.configure("masque", port, detour, lower, token=f.bad_token)
            with nexus_process(f.binary, config), udp_client(f.front) as (client, relay):
                packet(client, relay, 53, b"auth must fail", success=False)
            if select.select([peer.stdout], [], [], .1)[0]:
                raise RuntimeError("incorrect bearer authenticated at CONNECT-UDP peer")


def check_tuic(f, echo, tuic_port, trojan_port, ss_port):
    cases = (
        ("physical", "", "127.0.0.2", False),
        ("lower", f.trojan(trojan_port), "127.0.0.3", False),
        ("lower", f.ss(ss_port), "127.0.0.4", True),
    )
    for detour, lower, host, udp_stream in cases:
        with UdpObserver(tuic_port) as observer:
            config = f.configure("tuic", observer.port, detour, lower, udp_stream=udp_stream)
            with nexus_process(f.binary, config):
                socks5_tcp_echo(f.front, "127.0.0.1", echo.port, b"tuic stream" * 16)
                with udp_client(f.front) as (client, relay):
                    for payload in (b"tuic datagram", b"", b"t" * 1024):
                        packet(client, relay, echo.port, payload)
            if {source for source, _ in observer.sources} != {host}:
                raise RuntimeError(f"wrong TUIC egress: {observer.sources!r}")
            if detour == "physical" and observer.sources != {(host, f.source_port)}:
                raise RuntimeError(f"TUIC ignored direct UDP source port: {observer.sources!r}")


def check_invalid(f, ss_port):
    cases = (
        ("masque", "lower", f.ss(ss_port, uot=False), "", "requires a datagram-capable outbound"),
        ("tuic", "lower", f.ss(ss_port, uot=False), "", "requires a datagram-capable outbound"),
        ("tuic", "edge", "", "", "dependency cycle"),
        ("masque", "lower", f.trojan(ss_port), "udp-bind-port 1234;", "invalid MASQUE detour or socket settings"),
    )
    for protocol, detour, lower, extra, error in cases:
        before = list(f.dns.seen)
        config = f.configure(protocol, free_port(), detour, lower, extra=extra)
        result = subprocess.run([f.binary, "run", "--config", config], capture_output=True, text=True, timeout=4)
        if not result.returncode or error not in result.stderr or f.dns.seen != before:
            raise RuntimeError(f"invalid {protocol} detour reached startup or DNS: {result.stderr}")


def check_pending(f, echo):
    with socket.socket() as blackhole:
        blackhole.bind(("127.0.0.1", 0))
        blackhole.listen(4)
        blackhole.settimeout(3)
        lower = f.trojan(blackhole.getsockname()[1])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forbidden:
            forbidden.bind(("127.0.0.1", 0))
            remote = forbidden.getsockname()[1]
            config = f.configure("tuic", remote, lower=lower, timeout=350)
            with nexus_process(f.binary, config):
                started = time.monotonic()
                stream_request(f.front, echo.port, "target.test", success=False)
                if not .20 <= time.monotonic() - started < 1.7:
                    raise RuntimeError("TUIC did not honor the absolute lower connect deadline")
                with blackhole.accept()[0] as pending:
                    if not pending.recv(4096):
                        raise RuntimeError("lower deadline check never reached the TLS handshake")
                if select.select([forbidden], [], [], .1)[0]:
                    raise RuntimeError("TUIC fell back to direct UDP")
            config = f.configure("masque", remote, lower=lower, timeout=8000)
            with nexus_process(f.binary, config) as process, udp_client(f.front) as (client, relay):
                client.sendto(b"\0\0\0\1\x7f\0\0\1\0\x35pending", relay)
                with blackhole.accept()[0] as peer:
                    peer.settimeout(2)
                    if not peer.recv(4096):
                        raise RuntimeError("MASQUE stop check never reached the lower handshake")
                    process.send_signal(signal.SIGTERM)
                    if process.wait(timeout=2) or peer.recv(1) or select.select([forbidden], [], [], .1)[0]:
                        raise RuntimeError("MASQUE left a lower socket live or sent direct UDP")


def main(binary, peer):
    if f"Revision: {REVISION}" not in subprocess.check_output(["sing-box", "version"], text=True):
        raise RuntimeError("unexpected sing-box revision")
    with tempfile.TemporaryDirectory() as directory, DnsPeer() as dns, Echo() as echo:
        f = Fixture(Path(directory), binary, dns)
        trojan, ss = free_port(), free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            tuic = reserve.getsockname()[1]
        config = f.root / "sing-box.json"
        config.write_text(json.dumps({
            "log": {"level": "warn"},
            "inbounds": [
                {"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": ss,
                 "method": "2022-blake3-aes-128-gcm", "password": f.key.read_text()},
                {"type": "tuic", "tag": "tuic", "listen": "127.0.0.1", "listen_port": tuic,
                 "congestion_control": "cubic", "users": [{"uuid": f.uuid.read_text(), "password": f.secret.read_text()}],
                 "tls": {"enabled": True, "server_name": "localhost", "alpn": ["h3"],
                         "certificate_path": str(f.root / "cert"), "key_path": str(f.root / "key")}},
            ],
            "outbounds": [{"type": "direct", "tag": "direct", "inet4_bind_address": "127.0.0.4"}],
            "route": {"final": "direct"},
        }))
        with nexus_process(binary, trojan_listener(f, trojan)), running(
                ["sing-box", "run", "-c", config], ss, f.root / "sing-box.log"):
            check_masque(f, peer, trojan, ss)
            check_tuic(f, echo, tuic, trojan, ss)
            check_invalid(f, ss)
        check_pending(f, echo)
        if not {"quic.test", "lower.test"} <= {name for name, *_ in dns.seen}:
            raise RuntimeError("QUIC or lower bootstrap resolution did not run")
    print("TUIC TCP/UDP and CONNECT-UDP over Trojan and SS UoT, direct binding, rejection, timeout and stop passed")


if __name__ == "__main__":
    main(*(str(Path(arg).resolve(strict=True)) for arg in sys.argv[1:]))
