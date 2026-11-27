#!/usr/bin/env python3
"""Run the CONNECT-IP CLI through a local HTTP/3 peer with Capsule traffic."""
import argparse
from contextlib import ExitStack, contextmanager
from pathlib import Path
import select
import os
import base64
import json
import socket
import subprocess
import tempfile
import time

from detour_network import reserve, running
from dns_rule_support import nexus_process, udp_client
from types import SimpleNamespace
from udp_bind_port_network import certificate


def packet(host, payload):
    return b"\0\0\0\1" + socket.inet_aton(host) + b"\0\x35" + payload


def roundtrip(front, payload, *, host="198.51.100.42", timeout=2):
    with udp_client(front) as (client, relay):
        client.settimeout(timeout)
        wire = packet(host, payload)
        client.sendto(wire, relay)
        if client.recvfrom(65535)[0] != wire:
            raise RuntimeError(f"SOCKS CONNECT-IP echo mismatch for {host}")


def command(front, payload):
    with udp_client(front) as (client, relay):
        client.settimeout(.3)
        client.sendto(packet("198.51.100.42", payload), relay)
        try:
            client.recvfrom(65535)
        except TimeoutError:
            pass


def no_route(front, host):
    try:
        roundtrip(front, b"blocked", host=host, timeout=.25)
    except TimeoutError:
        return
    raise RuntimeError(f"traffic reached a withdrawn or unadvertised route for {host}")


@contextmanager
def ss_relay(root):
    from named_http3_detour import private_file
    upstream = reserve()
    key = base64.b64encode(bytes(range(16))).decode()
    secret_file = private_file(root, "sskey", key)
    proxy_config = root / "ss.json"
    proxy_config.write_text(json.dumps({
        "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": upstream,
                      "method": "2022-blake3-aes-128-gcm", "password": key}],
        "outbounds": [{"type": "direct", "tag": "direct", "inet4_bind_address": "127.0.0.4"}],
        "route": {"final": "direct"},
    }))
    lower = f'''outbound "lower" type="shadowsocks" {{
  server host="127.0.0.1" port={upstream}
  method "2022-blake3-aes-128-gcm"
  key-file "{secret_file}"
  udp-over-tcp "v2"
}}'''
    with running(["sing-box", "run", "-c", proxy_config], upstream, root / "ss.log"):
        yield upstream, lower


def run(binary, fixture, direct_binding=False, through_trojan=False, through_ss=False):
    with tempfile.TemporaryDirectory(prefix="nexus-masque-ip-") as tmp, ExitStack() as stack:
        root = Path(tmp)
        certificate(root)
        secret = root / "bearer"
        secret.write_text("approved\n")
        secret.chmod(0o600)
        env = os.environ.copy()
        physical, detour, lower = "", "", ""
        if direct_binding:
            source = "127.0.0.2"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind((source, 0))
                source_port = reservation.getsockname()[1]
            physical = f'{{ inet4-bind-address "{source}"; udp-bind-port {source_port}; }}'
            detour = 'detour "direct"'
            env["NEXUS_TEST_CONNECT_IP_SOURCE"] = f"{source}:{source_port}"
        if through_trojan:
            from named_http3_detour import private_file, trojan_listener
            password = private_file(root, "password", "connect-ip-detour")
            upstream = reserve()
            stack.enter_context(nexus_process(str(binary), trojan_listener(SimpleNamespace(root=root, secret=password), upstream)))
            detour = 'detour "lower"'
            lower = f'''outbound "lower" type="trojan" {{
  server host="127.0.0.1" port={upstream}
  authentication {{ password-file "{password}"; }}
  tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}'''
            env["NEXUS_TEST_CONNECT_IP_SOURCE"] = "127.0.0.3"
        if through_ss:
            _, lower = stack.enter_context(ss_relay(root))
            detour = 'detour "lower"'
            env["NEXUS_TEST_CONNECT_IP_SOURCE"] = "127.0.0.4"
        with subprocess.Popen([fixture, root / "cert", root / "key"], env=env, stdout=subprocess.PIPE, text=True) as peer:
            try:
                if not select.select([peer.stdout], [], [], 5)[0]:
                    raise RuntimeError("CONNECT-IP test peer did not start")
                port = int(peer.stdout.readline().rsplit(":", 1)[1])
                front = reserve()
                cfg = root / "ip.kdl"
                cfg.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {physical}
{lower}
outbound "edge" type="masque" {{
    mode "connect-ip"
    {detour}
    server host="127.0.0.1" port={port}
    authority "localhost"
    authentication {{ bearer-file "{secret}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
routing {{ final "edge"; }}
''')
                with nexus_process(str(binary), str(cfg)):
                    roundtrip(front, b"first")
                    no_route(front, "203.0.113.42")
                    command(front, b"disconnect")
                    deadline = time.monotonic() + 4
                    while True:
                        try:
                            roundtrip(front, b"recovered", timeout=.5)
                            break
                        except TimeoutError:
                            if time.monotonic() >= deadline:
                                raise
                    command(front, b"withdraw")
                    no_route(front, "198.51.100.42")
            finally:
                if peer.poll() is None:
                    peer.terminate()
                try:
                    peer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    peer.kill()
                    peer.wait()
            observed = peer.stdout.read().splitlines()
            if any(line not in observed for line in ("echo 1 first", "echo 1 disconnect", "echo 2 recovered", "echo 2 withdraw")):
                raise RuntimeError(f"missing CONNECT-IP peer evidence: {observed!r}")
    print("CONNECT-IP CLI accepted HTTP 202, obeyed routes, recovered after stream close and used Capsules")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("peer", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--direct-binding", action="store_true")
    mode.add_argument("--through-trojan", action="store_true")
    mode.add_argument("--through-ss", action="store_true")
    arguments = parser.parse_args()
    run(arguments.binary.resolve(strict=True), arguments.peer.resolve(strict=True), arguments.direct_binding, arguments.through_trojan, arguments.through_ss)
