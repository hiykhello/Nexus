#!/usr/bin/env python3
"""Observe the QUIC interface used by a named MASQUE CONNECT-UDP outbound."""

from contextlib import ExitStack
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time

from detour_network import reserve
from dns_rule_support import nexus_process
from network_selection_network import LINKS, TARGETS, address, default_route, peers, stall_primary_connects, udp
from tailscale_endpoint_network import line, process
from udp_bind_port_network import certificate


def exchange(association, expected=True):
    client, relay = association
    payload = b"\0\0\0" + address("127.0.0.1", 53) + b"masque-interface"
    client.sendto(payload, relay)
    try:
        reply, _ = client.recvfrom(4096)
    except TimeoutError:
        if expected:
            raise
        return
    assert expected and reply == payload, reply


def verify(binary, upstream):
    with tempfile.TemporaryDirectory(prefix="nexus-masque-networks-") as folder, ExitStack() as stack:
        root = Path(folder)
        certificate(root)
        token = root / "token"
        token.write_text("approved\n")
        token.chmod(0o600)
        front, port = reserve(), reserve()
        namespaces = peers(stack, reserve())
        servers = {}
        for name, pid in namespaces.items():
            for host in TARGETS:
                authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
                command = ["nsenter", "-t", str(pid), "-n", "--", upstream, "serve-network",
                           root / "cert", root / "key", authority]
                server = stack.enter_context(process(command))
                assert line(server).decode().strip() == authority
                servers[name, host] = server

        config = root / "proxy.kdl"

        def write(host):
            config.write_text(f'''schema-version 1
role "client"
inbounds {{
    socks5 "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
}}
outbound "direct" type="direct" {{
    network strategy="prefer" type="ethernet" fallback="wifi" fallback-delay-ms=350 {{
        interface "primary" type="ethernet"
        interface "backup" type="wifi"
    }}
}}
outbound "edge" type="masque" {{
    server host="{host}" port={port}
    authority "localhost"
    detour "direct"
    connect-timeout-ms 2100
    authentication {{ bearer-file "{token}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
routing {{ default-outbound "edge"; }}
''')

        def observe(name, host):
            server = servers[name, host]
            assert line(server) == b"/.well-known/masque/udp/127.0.0.1/53/\n"
            other = servers[("backup" if name == "primary" else "primary"), host]
            assert not select.select([other.stdout], [], [], .04)[0], (name, host)

        for host in TARGETS:
            write(host)
            with nexus_process(binary, config), ExitStack() as clients:
                primary = udp(front, clients)
                primary[0].settimeout(2.2)
                exchange(primary)
                observe("primary", host)
                with stall_primary_connects(namespaces["primary"], port, udp=True):
                    fallback = udp(front, clients)
                    fallback[0].settimeout(2.2)
                    start = time.monotonic()
                    exchange(fallback)
                    assert .30 <= time.monotonic()-start < 2.1
                    observe("backup", host)
                # The first connection is still usable after a failed new
                # handshake and the replacement path establishes separately.
                exchange(primary)
        for link in LINKS:
            default_route(link, False)
        with nexus_process(binary, config), ExitStack() as clients:
            exchange(udp(front, clients), expected=False)
        print("MASQUE CONNECT-UDP used both selected IPv4/IPv6 interfaces, recovered a silent primary and rejected missing paths")


if __name__ == "__main__":
    if sys.argv[1] == "--namespace":
        verify(*sys.argv[2:])
    else:
        cli, peer = (str(Path(path).resolve(strict=True)) for path in sys.argv[1:])
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--namespace", cli, peer],
                       check=True, timeout=50)
