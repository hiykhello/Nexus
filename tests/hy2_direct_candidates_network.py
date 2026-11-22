#!/usr/bin/env python3
"""Verify the physical Hysteria 2 interface policy with two veth peers."""
import contextlib
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from dns_rule_support import nexus_process
from detour_network import reserve
from network_selection_network import LINKS, TARGETS, default_route, peers, socks, stall_primary_connects, verify_tcp, verify_udp, udp
from tailscale_endpoint_network import eventually, process
from udp_bind_port_network import certificate

REVISION = "824dbcfb4dd0a95921840b1737b950cde590241e"


def server(stack, root, namespace, port, host, label):
    cfg = root / f"{label}-{host}.json"
    cfg.write_text(json.dumps({
        "log": {"level": "error"},
        "inbounds": [{"type": "hysteria2", "listen": host, "listen_port": port,
                      "users": [{"name": "test", "password": "network-path"}],
                      "tls": {"enabled": True, "certificate_path": str(root / "cert"),
                              "key_path": str(root / "key")}}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }))
    ns = ["nsenter", "-t", str(namespace), "-n", "--"]
    stack.enter_context(process([*ns, "sing-box", "run", "-c", cfg]))
    family = "-6" if ":" in host else "-4"
    eventually(lambda: f":{port} " in subprocess.check_output([*ns, "ss", family, "-H", "-nlu"], text=True))


def verify(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-hy2-networks-") as folder, contextlib.ExitStack() as stack:
        root = Path(folder)
        certificate(root)
        password = root / "password"
        password.write_text("network-path")
        password.chmod(0o600)
        front, port, echo = reserve(), reserve(), reserve()
        namespaces = peers(stack, echo)
        for label, pid in namespaces.items():
            for host in TARGETS:
                server(stack, root, pid, port, host, label)
        for host in TARGETS:
            conf = root / "nexus.kdl"
            conf.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{
    network strategy="prefer" type="ethernet" fallback="wifi" fallback-delay-ms=350 {{
        interface "primary" type="ethernet"
        interface "backup" type="wifi"
    }}
}}
outbound "edge" type="hysteria2" {{
    server host="{host}" port={port}
    detour "direct"
    connect-timeout-ms 2400
    authentication {{ password-file "{password}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
routing {{ default-outbound "edge"; }}
''')
            with nexus_process(binary, conf):
                with contextlib.ExitStack() as clients:
                    connection, code, _ = socks(front, 1, host, echo)
                    clients.enter_context(connection)
                    assert code == 0, code
                    verify_tcp(connection, "primary")
                    verify_udp(udp(front, clients), host, echo, "primary")
                with stall_primary_connects(namespaces["primary"], port, udp=True):
                    with contextlib.ExitStack() as clients:
                        start = time.monotonic()
                        connection, code, _ = socks(front, 1, host, echo)
                        clients.enter_context(connection)
                        assert code == 0 and .30 <= time.monotonic()-start < 2.4, code
                        verify_tcp(connection, "backup")
                        # Each new UDP association creates a fresh QUIC connection.
                        association = udp(front, clients)
                        association[0].settimeout(2)
                        verify_udp(association, host, echo, "backup")
        for link in LINKS:
            default_route(link, False)
        with nexus_process(binary, conf):
            connection, code, _ = socks(front, 1, host, echo)
            with connection:
                assert code != 0
    print("Hysteria 2 TCP and UDP honored IPv4/IPv6 interface fallback and rejected missing candidates")


if __name__ == "__main__":
    if sys.argv[1] == "--namespace":
        verify(sys.argv[2])
    else:
        version = subprocess.run(["sing-box", "version"], text=True, check=True, capture_output=True).stdout
        assert f"Revision: {REVISION}" in version, version
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--namespace", sys.argv[1]],
                       check=True, timeout=60)
