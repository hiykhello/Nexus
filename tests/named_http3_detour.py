#!/usr/bin/env python3
"""Exercise named HTTP/3 through production packet outbounds and a chained relay."""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

from detour_network import running
from dns_rule_support import DnsPeer, free_port, nexus_process
from hy2_outbound_singbox import REVISION
from named_http_rule_fetch import RULES
from quic_ech_cli import generate
from tuic_singbox import stop_proc
from udp_bind_port_network import certificate


def private_file(root, name, value):
    path = root / name
    path.write_text(value)
    path.chmod(0o600)
    return path


class Fixture:
    def __init__(self, binary, root, origin_dns, bootstrap_dns):
        self.binary, self.root = binary, root
        self.origin_dns, self.bootstrap_dns = origin_dns, bootstrap_dns
        self.front = free_port()
        self.origin = 0
        self.direct_port = free_port()
        certificate(root)
        self.secret = private_file(root, "password", "h3-packet-secret")
        self.wrong_secret = private_file(root, "wrong-password", "incorrect")
        self.sskey = private_file(root, "sskey", base64.b64encode(bytes(range(16))).decode())
        self.output = root / "published"
        self.config = root / "client.kdl"
        self.rules = RULES + b"//" + b"r" * 12000 + b"\n"
        self.source = root / "rules"
        self.source.write_bytes(self.rules)
        self.ech, self.keys = generate(root, "valid")
        self.bad_ech, _ = generate(root, "wrong")
        self.pin = hashlib.sha256(self.rules).hexdigest()

    @contextmanager
    def peer(self, fixture, source_host):
        env = dict(os.environ, NEXUS_TEST_ECH_KEYS=str(self.keys), NEXUS_TEST_SOURCE_HOST=source_host,
                   NEXUS_TEST_SOURCE_PORT="")
        with subprocess.Popen([fixture, self.root / "cert", self.root / "key", self.source],
                              env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                if not select.select([process.stdout], [], [], 5)[0]:
                    raise RuntimeError("independent HTTP/3 peer did not start")
                line = process.stdout.readline().strip()
                if not line.startswith(b"127.0.0.1:"):
                    raise RuntimeError(f"HTTP/3 peer did not bind: {line!r}")
                self.origin = int(line.rsplit(b":", 1)[1])
                yield process
            finally:
                stop_proc(process)
                diagnostics = process.stderr.read()
                if b"received UDP payload" in diagnostics or b"unexpected UDP source" in diagnostics:
                    raise RuntimeError(f"proxied QUIC used an unexpected socket or datagram size: {diagnostics!r}")

    def trojan(self, name, port, password, detour, connect_by=1400):
        return f'''outbound "{name}" type="trojan" {{
  server host="{name}.test" port={port}; bootstrap-resolver "bootstrap"; detour "{detour}";
  authentication {{ password-file "{password}"; }}
  tls {{ server-name "localhost"; ca-file "{self.root / 'cert'}"; verify #true; }}
  connect-timeout-ms {connect_by}
}}'''

    def ss(self, port, uot, detour):
        option = 'udp-over-tcp "v2";' if uot else ""
        return f'''outbound "ss" type="shadowsocks" {{
  server host="ss.test" port={port}; bootstrap-resolver "bootstrap"; detour "{detour}";
  method "2022-blake3-aes-128-gcm"; key-file "{self.sskey}"; {option}
}}'''

    def configure(self, outbounds, name, timeout=2500, ech=None):
        ech = self.ech if ech is None else ech
        self.config.write_text(f'''schema-version 1
role "client"
inbound "front" type="socks5" {{ listen host="127.0.0.1" port={self.front}; authentication "none"; }}
outbound "physical" type="direct" {{ inet4-bind-address "127.0.0.2"; udp-bind-port {self.direct_port}; }}
{outbounds}
dns {{
  server "bootstrap" type="udp" host="127.0.0.1" port={self.bootstrap_dns.port}
  server "origin" type="udp" host="127.0.0.1" port={self.origin_dns.port}
  final "bootstrap"; strategy "ipv4_only";
}}
http-clients {{
  updates {{
    outbound "{name}"; domain-resolver "origin"; ca-file "{self.root / 'cert'}";
    protocol "h3"; timeout-ms {timeout}; max-response-bytes 16000; max-udp-payload-size 1200;
    ech-config-file "{ech}";
  }}
}}
routing {{ default-outbound "physical"; }}
''')

    def arguments(self, path):
        return [self.config, "updates", f"https://localhost:{self.origin}/{path}", "kdl", self.output,
                "--sha256", self.pin]

    def fetch(self, path="rules"):
        return subprocess.run([self.binary, "rule", "fetch", *self.arguments(path)],
                              capture_output=True, text=True, timeout=5)

    def success(self, peer, expected_dns):
        self.output.write_bytes(b"old")
        origin_before, lower_before = len(self.origin_dns.seen), len(self.bootstrap_dns.seen)
        result = self.fetch()
        if result.returncode or self.output.read_bytes() != self.rules:
            raise RuntimeError(f"HTTP/3 through {expected_dns} failed: {result.stderr}")
        if not select.select([peer.stdout], [], [], 2)[0] or peer.stdout.readline() != b"rules request\n":
            raise RuntimeError("HTTP/3 peer did not authenticate the rules request")
        observed_origin = set(self.origin_dns.seen[origin_before:])
        observed_lower = {name for name, *_ in self.bootstrap_dns.seen[lower_before:]}
        if observed_origin != {("localhost", 1, "udp")} or observed_lower != set(expected_dns):
            raise RuntimeError(f"crossed origin and bootstrap DNS: {observed_origin!r}, {observed_lower!r}")

    def failure(self, peer, path="rules", diagnostic="HTTP/3"):
        before = self.output.read_bytes()
        result = self.fetch(path)
        if (not result.returncode or diagnostic not in result.stderr or self.output.read_bytes() != before):
            raise RuntimeError(f"failed HTTP/3 request affected publication: {result.stderr}")
        if select.select([peer.stdout], [], [], .08)[0]:
            raise RuntimeError(f"a failed detour reached the HTTP origin: {peer.stdout.readline()!r}")

    def stop_watching(self, await_request):
        before = self.output.read_bytes()
        with subprocess.Popen([self.binary, "rule", "watch", "100", *self.arguments("watch")],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as watcher:
            try:
                await_request()
                watcher.send_signal(signal.SIGTERM)
                _, diagnostics = watcher.communicate(timeout=2)
                if watcher.returncode or self.output.read_bytes() != before:
                    raise RuntimeError(f"watcher did not drain: {diagnostics!r}")
            finally:
                stop_proc(watcher)


def trojan_listener(fixture, port):
    config = fixture.root / "relay.kdl"
    config.write_text(f'''schema-version 1
role "server"
inbound "edge" type="trojan" {{
  listen host="127.0.0.1" port={port}
  authentication {{ user "rules" password-file="{fixture.secret}"; }}
  tls {{ certificate-file "{fixture.root / 'cert'}"; private-key-file "{fixture.root / 'key'}"; }}
}}
outbound "physical" type="direct" {{ inet4-bind-address "127.0.0.3"; }}
routing {{ default-outbound "physical"; }}
''')
    return config


def check_trojan(f, peer_binary, port):
    via = f.trojan("trojan", port, f.secret, "physical")
    with f.peer(peer_binary, "127.0.0.3") as peer:
        f.configure(via, "trojan")
        f.success(peer, ("trojan.test",))
        f.configure(via, "trojan", ech=f.bad_ech)
        f.failure(peer)
        f.configure(f.trojan("trojan", port, f.wrong_secret, "physical"), "trojan")
        f.failure(peer)
        f.configure(via, "trojan", timeout=8000)

        def reached():
            if not select.select([peer.stdout], [], [], 5)[0] or peer.stdout.readline() != b"watch request\n":
                raise RuntimeError("proxied HTTP/3 watch did not reach the origin")

        f.stop_watching(reached)
        f.success(peer, ("trojan.test",))


def check_ss_and_hy2(f, peer_binary, trojan_port):
    port = free_port()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        hy2_port = reserve.getsockname()[1]
    box = f.root / "ss.json"
    box.write_text(json.dumps({
        "log": {"level": "debug"},
        "inbounds": [
            {"type": "shadowsocks", "tag": "edge", "listen": "127.0.0.1", "listen_port": port,
             "method": "2022-blake3-aes-128-gcm", "password": f.sskey.read_text()},
            {"type": "hysteria2", "tag": "quic", "listen": "127.0.0.1", "listen_port": hy2_port,
             "users": [{"password": f.secret.read_text()}],
             "tls": {"enabled": True, "certificate_path": str(f.root / "cert"),
                     "key_path": str(f.root / "key"), "alpn": ["h3"]}},
        ],
        "outbounds": [{"type": "direct", "tag": "direct", "inet4_bind_address": "127.0.0.4"}],
        "route": {"final": "direct"},
    }))
    with running(["sing-box", "run", "-c", box], port, f.root / "sing-box.log"), f.peer(peer_binary, "127.0.0.4") as peer:
        f.configure(f.ss(port, True, "physical"), "ss")
        f.success(peer, ("ss.test",))
        f.configure(f.ss(port, False, "physical"), "ss")
        before = len(f.origin_dns.seen), len(f.bootstrap_dns.seen)
        f.failure(peer, diagnostic="outbound does not support datagrams")
        if (len(f.origin_dns.seen), len(f.bootstrap_dns.seen)) != before:
            raise RuntimeError("a TCP-only outbound reached DNS")

        # The UDP packets ride the SS UoT stream, and Trojan dials the SS server.
        via = f.trojan("trojan", trojan_port, f.secret, "physical") + "\n" + f.ss(port, True, "trojan")
        log = f.root / "sing-box.log"
        before = log.stat().st_size
        f.configure(via, "ss")
        f.success(peer, ("trojan.test", "ss.test"))
        if b"127.0.0.3" not in log.read_bytes()[before:]:
            raise RuntimeError("chained SS server did not observe the Trojan egress address")

        hy2 = f'''outbound "hy2" type="hysteria2" {{
  server host="hy2.test" port={hy2_port}; bootstrap-resolver "bootstrap"; detour "physical";
  authentication {{ password-file "{f.secret}"; }}
  tls {{ server-name "localhost"; ca-file "{f.root / 'cert'}"; verify #true; }}
}}'''
        f.configure(hy2, "hy2")
        f.success(peer, ("hy2.test",))


def check_pending(f):
    with socket.socket() as lower:
        lower.bind(("127.0.0.1", 0))
        lower.listen(2)
        lower.settimeout(3)
        port = lower.getsockname()[1]
        f.configure(f.trojan("trojan", port, f.secret, "physical", connect_by=350), "trojan", timeout=8000)
        started = time.monotonic()
        result = f.fetch()
        elapsed = time.monotonic() - started
        with lower.accept()[0] as suspended:
            if not suspended.recv(4096):
                raise RuntimeError("deadline check did not reach the lower TLS connection")
        if (not result.returncode or "outbound packet connection failed" not in result.stderr or
                not .25 <= elapsed < 1.8 or f.output.read_bytes() != f.rules):
            raise RuntimeError(f"lower connect budget failed in {elapsed:.3f}s: {result.stderr}")

        f.configure(f.trojan("trojan", port, f.secret, "physical", connect_by=8000), "trojan", timeout=8000)
        pending = []

        def reached():
            connection, _ = lower.accept()
            pending.append(connection)
            connection.settimeout(2)
            if not connection.recv(4096):
                raise RuntimeError("cancel check did not reach the lower TLS connection")

        try:
            f.stop_watching(reached)
            if pending[0].recv(1):
                raise RuntimeError("canceled TLS transport remained open")
        finally:
            for connection in pending:
                connection.close()


def main(binary, peer):
    version = subprocess.check_output(["sing-box", "version"], text=True)
    if f"Revision: {REVISION}" not in version:
        raise RuntimeError("unexpected sing-box revision")
    with tempfile.TemporaryDirectory() as directory, DnsPeer() as origin_dns, DnsPeer() as bootstrap_dns:
        fixture = Fixture(binary, Path(directory), origin_dns, bootstrap_dns)
        trojan_port = free_port()
        with nexus_process(binary, trojan_listener(fixture, trojan_port)):
            check_trojan(fixture, peer, trojan_port)
            check_ss_and_hy2(fixture, peer, trojan_port)
        check_pending(fixture)
    print("HTTP/3 over Trojan UDP, SS UoT and Hysteria2, chained egress, ECH, DNS, outbound deadline and cancellation passed")


if __name__ == "__main__":
    main(*(str(Path(arg).resolve(strict=True)) for arg in sys.argv[1:]))
