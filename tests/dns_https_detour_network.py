#!/usr/bin/env python3
"""Authenticate DoH and DoQ through a real proxy outbound."""
import argparse
import base64
import socket
import struct
import subprocess
import tempfile
from pathlib import Path

from anytls_network import Origin
from detour_network import running
from dns_encrypted_network import peer, query
from dns_rule_support import (DnsPeer, Echo, connect, datagram_request, exact, free_port,
                              nexus_process, ss_client)
from named_http_rule_fetch import Origin as RuleOrigin, RULES
from udp_bind_port_network import certificate


def socks(front, name, port, succeeds):
    with connect(front) as client:
        client.sendall(b"\x05\x01\0")
        assert exact(client, 2) == b"\x05\0"
        host = name.encode()
        client.sendall(b"\x05\x01\0\x03" + bytes([len(host)]) + host + struct.pack("!H", port))
        header = exact(client, 4)
        exact(client, 6 if header[3] == 1 else 18)
        assert (header[1] == 0) == succeeds, header
        if succeeds:
            payload = b"DoH through authenticated TCP"
            client.sendall(payload)
            assert exact(client, len(payload)) == payload
            client.shutdown(socket.SHUT_WR)
            assert client.recv(1) == b""


def verify(binary, fixture, protocol, host, pooled=False):
    with tempfile.TemporaryDirectory(prefix="nexus-proxy-doh-") as directory:
        root = Path(directory)
        certificate(root)
        password = root / "password"
        password.write_text("doh-proxy-secret\n")
        password.chmod(0o600)
        front, lower = free_port(), free_port()
        lower_config = root / "lower.kdl"
        lower_config.write_text(f'''schema-version 1
role "server"
inbounds {{
  trojan "edge" {{
    listen host="127.0.0.1" port={lower}
    authentication {{ user "dns" password-file="{password}"; }}
    tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
  }}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
        origin_dir = root / "doh"
        origin_dir.mkdir()
        with peer(fixture, origin_dir, protocol, host, trace_pool=pooled) as (port, ca, read_event):
            connections = {}
            def event():
                line = read_event()
                fields = line.split()
                if pooled and len(fields)==4 and fields[0]=="request":
                    connections[fields[1]] = fields.pop()
                    return " ".join(fields)
                return line

            config = root / "front.kdl"
            transport = {"quic": "quic", "h3": "https3"}.get(protocol, "https")
            http_path = ' path="/resolve?profile=edge"' if transport != "quic" else ""
            source = f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "dns-proxy" type="trojan" {{
  server host="127.0.0.1" port={lower}
  authentication {{ password-file "{password}"; }}
  tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
outbound "inner" type="selector" {{
  member "dns-proxy"
  member "direct"
  selected "dns-proxy"
}}
outbound "dns-egress" type="selector" {{ member "inner"; }}
dns {{
  server "upstream" type="{transport}" host="{host}" port={port} server-name="dns.test" ca-file="{ca}"{http_path} detour="dns-egress"
  final "upstream"
  strategy "ipv4_only"
  disable-cache #true
}}
routing {{ final "direct"; }}
'''
            config.write_text(source)
            with Origin(expected=2) as origin, nexus_process(binary, config):
                socks(front, "before.test", origin.port, False)
                with running([binary, "run", "--config", lower_config], lower, root / "lower.log"):
                    socks(front, "first.test", origin.port, True)
                    version = {"h1": "HTTP/1.1", "h2": "HTTP/2.0", "h3": "HTTP/3.0"}.get(protocol)
                    first = event()
                    if protocol != "quic":
                        assert first == f"request first.test {version}", first
                    socks(front, "second.test", origin.port, True)
                    second = event()
                    if protocol == "quic":
                        fields_a, fields_b = first.split(), second.split()
                        assert fields_a[:2] == ["request", "first.test"], first
                        assert fields_b[:2] == ["request", "second.test"], second
                        assert fields_a[2] == fields_b[2], (first, second)
                        assert fields_a[3] != fields_b[3], (first, second)
                    else:
                        assert second == f"request second.test {version}", second
                    if pooled:
                        assert connections["first.test"] == connections["second.test"], connections
                    origin.wait()
                socks(front, "after.test", origin.port, False)

            dns_port = free_port()
            config.write_text(source.replace("dns {", f'dns {{\n  listen host="127.0.0.1" port={dns_port}'))
            with nexus_process(binary, config):
                query(dns_port, "listener-offline.test", code=2)
                with running([binary, "run", "--config", lower_config], lower, root / "lower.log"):
                    query(dns_port, "listener-udp.test")
                    assert event().split()[:2] == ["request", "listener-udp.test"]
                    query(dns_port, "listener-tcp.test", transport=socket.SOCK_STREAM, kind=28)
                    assert event().split()[:2] == ["request", "listener-tcp.test"]
                    if pooled:
                        assert connections["listener-udp.test"] == connections["listener-tcp.test"], connections
            if protocol == "h2" and host == "127.0.0.1":
                with DnsPeer() as bootstrap:
                    configured = source.replace(
                        f'server host="127.0.0.1" port={lower}',
                        f'server host="proxy.test" port={lower}\n  bootstrap-resolver "bootstrap";',
                    ).replace(
                        f'host="{host}" port={port} server-name',
                        f'host="resolver.test" port={port} domain-resolver="bootstrap" server-name',
                    ).replace("dns {", f'''dns {{
  listen host="127.0.0.1" port={dns_port}
  server "bootstrap" type="udp" host="127.0.0.1" port={bootstrap.port}''')
                    config.write_text(configured)
                    with running([binary, "run", "--config", lower_config], lower, root / "lower.log"):
                        with nexus_process(binary, config):
                            query(dns_port, "bootstrapped.test")
                            assert event() == "request bootstrapped.test HTTP/2.0"
                    assert bootstrap.count("proxy.test", 1) >= 1, bootstrap.seen
                    assert bootstrap.count("resolver.test", 1) >= 1, bootstrap.seen
            if protocol == "h2" and host == "127.0.0.1":
                key = bytes(range(16))
                key_file = root / "ss-key"
                key_file.write_bytes(base64.b64encode(key))
                key_file.chmod(0o600)
                ss_port = free_port()
                ss = f'''inbound "ss" type="shadowsocks" {{
  listen host="127.0.0.1" port={ss_port}
  method "2022-blake3-aes-128-gcm"
  key-file "{key_file}"
}}
'''
                config.write_text(source.replace('role "client"','role "server"') + ss)
                with running([binary, "run", "--config", lower_config], lower, root / "lower.log"):
                    with nexus_process(binary, config, listeners=2), Echo() as echo, ss_client(root, ss_port, key) as (udp, relay):
                        datagram_request(udp, relay, echo.port, "ss-udp.test")
                        assert event() == "request ss-udp.test HTTP/2.0"

                fetch_config = source.replace('outbound "direct" type="direct"',
                    'outbound "direct" type="direct" { inet4-bind-address "127.0.0.2"; }')
                fetch_config += f'''http-clients {{
  updates {{
    outbound "direct"
    domain-resolver "upstream"
    ca-file "{root / "cert"}"
    protocol "http/1.1"
    timeout-ms 2500
  }}
}}
'''
                config.write_text(fetch_config)
                with RuleOrigin(root) as web:
                    output = root / "rules.kdl"
                    command = [binary, "rule", "fetch", config, "updates",
                               f"https://localhost:{web.port}/rules", "kdl", output]
                    offline = subprocess.run(command, capture_output=True, timeout=5)
                    assert offline.returncode and not web.seen, offline.stderr
                    with running([binary, "run", "--config", lower_config], lower, root / "lower.log"):
                        online = subprocess.run(command, capture_output=True, timeout=5)
                        assert online.returncode == 0, online.stderr
                        assert output.read_bytes() == RULES
                        assert event() == "request localhost HTTP/2.0"
                        assert web.seen == [("127.0.0.2", b"GET", b"/rules", b"HTTP/1.1")], web.seen
            if protocol == "h3":
                # The same peer also exercises the physical branch and its Age handling.
                physical = source.replace(' detour="dns-egress"', ' detour="direct"')
                config.write_text(physical.replace("dns {", f'dns {{\n  listen host="127.0.0.1" port={dns_port}'))
                with nexus_process(binary, config):
                    query(dns_port, "direct-h3.test", ttl=29)
                    assert event() == "request direct-h3.test HTTP/3.0"
                    query(dns_port, "wrong-type.test", code=2)
                    assert event() == "request wrong-type.test HTTP/3.0"
                    query(dns_port, "redirect.test", code=2)
                    assert event() == "request redirect.test HTTP/3.0"
            config.write_text(source.replace(f'server host="127.0.0.1" port={lower}',
                f'server host="proxy.test" port={lower}\n  bootstrap-resolver "upstream";'))
            cycle = subprocess.run([binary, "run", "--config", config], capture_output=True, timeout=3)
            assert cycle.returncode and b"outbound or DNS dependency cycle" in cycle.stderr, cycle.stderr
    print(f"{protocol} {host}: {transport} through Trojan, offline failure and bootstrap cycle rejection passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nexus", type=Path)
    parser.add_argument("peer", type=Path)
    parser.add_argument("--assert-h2-pool", action="store_true")
    parser.add_argument("--assert-h3-pool", action="store_true")
    args = parser.parse_args()
    for protocol in ("h1", "h2", "h3", "quic"):
        for host in ("127.0.0.1", "::1"):
            verify(args.nexus.resolve(strict=True), args.peer.resolve(strict=True), protocol, host,
                   (protocol=="h2" and args.assert_h2_pool) or (protocol=="h3" and args.assert_h3_pool))


if __name__ == "__main__":
    main()
