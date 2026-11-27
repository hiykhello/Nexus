#!/usr/bin/env python3
"""Exercise the alternate H3 CONNECT-IP profile against a strict Go peer."""
from pathlib import Path
import os
import select
import socket
import subprocess
import sys
import tempfile
import time

from dns_rule_support import nexus_process, udp_client
from detour_network import reserve
from udp_bind_port_network import certificate


def exchange(front, host, data, timeout=1, oversized_probe=False):
    ipv6 = ":" in host
    address = socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET, host)
    request = b"\0\0\0" + (b"\x04" if ipv6 else b"\x01") + address + b"\0\x35" + data
    with udp_client(front) as (conn, relay):
        conn.settimeout(timeout)
        conn.sendto(request, relay)
        assert conn.recvfrom(65535)[0] == request
        if oversized_probe:
            conn.settimeout(.15)
            try:
                extra=conn.recvfrom(65535)[0]
            except TimeoutError:
                pass
            else:
                raise AssertionError(f"oversized peer packet leaked into SOCKS: {len(extra)} bytes")


def test(binary, peer, root):
    certificate(root)
    bearer = root / "bearer"
    bearer.write_text("approved\n")
    bearer.chmod(0o600)
    with subprocess.Popen([peer, root / "cert", root / "key"], stdout=subprocess.PIPE, bufsize=0,
                          env=dict(os.environ, NEXUS_TEST_WARP="1")) as process:
        try:
            assert select.select([process.stdout], [], [], 5)[0]
            port = int(process.stdout.readline().rsplit(b":", 1)[1])
            front = reserve()
            path = root / "warp.kdl"
            config = f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="masque" {{
  server host="127.0.0.1" port={port}
  authority "localhost"
  authentication {{ bearer-file "{bearer}"; }}
  tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
  mode "connect-ip"
  protocol "cf-connect-ip"
  path "/"
  header "Cf-Connect-Proto" "cf-connect-ip"
  header "User-Agent" "warp-fixture"
  local-address "10.10.0.2/32"
  local-address "fd10::2/128"
  mtu 1280
}}
routing {{ final "edge"; }}
'''
            path.write_text(config)
            with nexus_process(binary, path):
                for host in ("198.51.100.42", "2001:db8:42::42"):
                    exchange(front, host, b"mtu-report", oversized_probe=True)
                    exchange(front, host, b"x" * 1200)
                try:
                    exchange(front, "198.51.100.42", b"disconnect", timeout=.3)
                except TimeoutError:
                    pass
                deadline = time.monotonic() + 5
                while True:
                    try:
                        exchange(front, "2001:db8:42::42", b"reconnected")
                        break
                    except TimeoutError:
                        if time.monotonic() >= deadline:
                            raise
                exchange(front, "198.51.100.42", b"v4-after-reconnect")
            events = []
            while select.select([process.stdout], [], [], .15)[0]:
                line = process.stdout.readline().decode().strip()
                if not line:
                    break
                events.append(line)
            assert any("reconnected" in e for e in events) and len({e.split()[1] for e in events if e.startswith("echo ")}) >= 2
            print("H3 cf-connect-ip path / and required headers, static IPv4/IPv6, oversized inbound frames excluded at MTU 1280 and fresh CONNECT after close")
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="nexus-94d-masque-") as name:
        test(*(Path(value).resolve(strict=True) for value in sys.argv[1:3]), Path(name))
