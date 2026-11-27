#!/usr/bin/env python3
"""Verify physical network selection for the standalone MASQUE CONNECT-IP TUN."""
from contextlib import ExitStack, nullcontext
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time

from detour_network import reserve
from masque_ip_tun import NAME, addresses, exchange, routes, wait_until
from network_selection_network import LINKS, TARGETS, default_route, peers, stall_primary_connects
from tailscale_endpoint_network import line, process
from udp_bind_port_network import certificate


def verify(cli, fixture):
    with tempfile.TemporaryDirectory(prefix="nexus-connect-ip-networks-") as folder, ExitStack() as stack:
        root = Path(folder)
        certificate(root)
        token = root / "token"
        token.write_text("approved\n")
        token.chmod(0o600)
        port = reserve()
        namespaces = peers(stack, reserve())
        servers = {}
        for link in LINKS:
            label, source4, _, source6, _, _ = link
            for family, host, source in zip((4, 6), TARGETS, (source4, source6), strict=True):
                authority = f"[{host}]:{port}" if family == 6 else f"{host}:{port}"
                command = ["nsenter", "-t", str(namespaces[label]), "-n", "--", fixture,
                           root / "cert", root / "key", "request"]
                environment = dict(os.environ, NEXUS_TEST_CONNECT_IP_LISTEN=authority,
                                   NEXUS_TEST_CONNECT_IP_SOURCE=f"[{source}]" if family == 6 else source)
                server = stack.enter_context(process(command, env=environment))
                assert line(server).decode().strip() == authority
                servers[label, host] = server

        config = root / "nexus.kdl"
        for host in TARGETS:
            config.write_text(f'''schema-version 1
role "client"
inbound "tun" type="tun" {{
    interface-name "{NAME}"
    connect-ip-outbound "edge"
    connect-ip-route "198.51.100.32/28"
    connect-ip-route "2001:db8:42::/96"
}}
outbound "direct" type="direct" {{
    network strategy="prefer" type="ethernet" fallback="wifi" fallback-delay-ms=350 {{
        interface "primary" type="ethernet"
        interface "backup" type="wifi"
    }}
}}
outbound "edge" type="masque" {{
    mode "connect-ip"
    server host="{host}" port={port}
    authority "localhost"
    detour "direct"
    connect-timeout-ms 2400
    authentication {{ bearer-file "{token}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
routing {{ final "direct"; }}
''')
            for label in ("primary", "backup"):
                impairment = stall_primary_connects(namespaces["primary"], port, udp=True) if label == "backup" else nullcontext()
                print(f"CONNECT-IP outer {host}, expected {label}", flush=True)
                with impairment, process([cli, "run", "--config", config]) as nexus:
                    start = time.monotonic()
                    wait_until(nexus, lambda: addresses() == {"10.10.0.2", "fd10::2"})
                    assert routes() == {"198.51.100.32/28", "2001:db8:42::/96"}
                    if label == "backup":
                        assert .30 <= time.monotonic() - start < 2.4
                    selected = servers[label, host]
                    other = servers["primary" if label == "backup" else "backup", host]
                    for family, inner in ((socket.AF_INET, "198.51.100.42"), (socket.AF_INET6, "2001:db8:42::42")):
                        payload = b"path-" + label.encode()
                        exchange(family, inner, payload)
                        assert line(selected).strip().split()[-1] == payload
                    assert not select.select([other.stdout], [], [], .04)[0]
                assert not addresses() and not routes()
        for link in LINKS:
            default_route(link, False)
        with process([cli, "run", "--config", config]) as nexus:
            time.sleep(.65)
            assert nexus.poll() is None and not addresses() and not routes()
    print("CONNECT-IP TUN selected the configured IPv4/IPv6 physical path, recovered a silent primary and skipped absent paths")


if __name__ == "__main__":
    if sys.argv[1] == "--namespace":
        verify(*sys.argv[2:])
    else:
        cli, fixture = (str(Path(binary).resolve(strict=True)) for binary in sys.argv[1:])
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--namespace", cli, fixture],
                       check=True, timeout=50)
