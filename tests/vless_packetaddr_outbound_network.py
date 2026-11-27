#!/usr/bin/env python3
"""Exercise Nexus VLESS UDP encodings against a pinned independent server."""
import argparse
import contextlib
import json
import socket
import subprocess
import tempfile
from pathlib import Path

from detour_network import reserve, running
from dns_rule_support import nexus_process, udp_client
from udp_bind_port_network import certificate

UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"
REVISION = "824dbcfb4dd0a95921840b1737b950cde590241e"


def verify(cli, root, port, fast_open, encoding, lower=None):
    front = reserve()
    cfg = root / "client.kdl"
    dial = "tcp-fast-open #true" if fast_open else ""
    detour = 'detour "lower"' if lower else ""
    lower_outbound = f'''outbound "lower" type="trojan" {{
    server host="127.0.0.1" port={lower}
    authentication {{ password-file "{root / 'password'}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}''' if lower else ""
    rules = ('tcp-program sniff-timeout-ms=200 udp=#true unknown="skip" { rule action="route" outbound="edge"; }; '
             if fast_open else "")
    cfg.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
    server host="127.0.0.1" port={port}
    packet-encoding "{encoding}"
    {dial}
    {detour}
    authentication {{ uuid-file "{root / 'uuid'}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
{lower_outbound}
routing {{ {rules}final "edge"; }}
''')
    with nexus_process(cli, cfg), udp_client(front) as (client, relay), contextlib.ExitStack() as stack:
        endpoints = []
        for family, address, tag in ((socket.AF_INET, "127.0.0.1", 1),
                                     (socket.AF_INET6, "::1", 4),
                                     (socket.AF_INET, "127.0.0.1", 1)):
            origin = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
            origin.settimeout(4)
            origin.bind((address, 0))
            header = b"\0\0\0" + bytes([tag]) + socket.inet_pton(family, address)
            header += origin.getsockname()[1].to_bytes(2, "big")
            endpoints.append((origin, header))
        for payload in (b"datagram", b"", b"second-datagram"):
            for origin, header in endpoints:
                client.sendto(header + payload, relay)
                data, peer = origin.recvfrom(65535)
                assert data == payload, (header, data)
                origin.sendto(data, peer)
                response, _ = client.recvfrom(65535)
                assert response == header + payload, (header, response)
    print(f"VLESS {encoding} to pinned sing-box passed three targets, dual-stack boundaries and empty UDP (TFO={fast_open}, Trojan detour={lower is not None})")


def main(cli, encoding):
    version = subprocess.run(["sing-box", "version"], capture_output=True, text=True, check=True).stdout
    assert f"Revision: {REVISION}" in version, version
    with tempfile.TemporaryDirectory(prefix="nexus-vless-packetaddr-") as temp:
        root = Path(temp)
        certificate(root)
        (root / "uuid").write_text(UUID)
        (root / "uuid").chmod(0o600)
        port = reserve()
        lower = reserve()
        while lower == port:
            lower = reserve()
        (root / "password").write_text("fixed-test-pass")
        (root / "password").chmod(0o600)
        cfg = root / "server.json"
        tls = {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")}
        cfg.write_text(json.dumps({
            "log": {"level": "error"},
            "inbounds": [
                {"type": "vless", "listen": "127.0.0.1", "listen_port": port,
                 "users": [{"uuid": UUID}], "tls": tls},
                {"type": "trojan", "listen": "127.0.0.1", "listen_port": lower,
                 "users": [{"password": "fixed-test-pass"}], "tls": tls},
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }))
        with running(["sing-box", "run", "-c", cfg], port, root / "sing-box.log"):
            verify(cli, root, port, False, encoding)
            verify(cli, root, port, True, encoding)
            if encoding == "fixed":
                verify(cli, root, port, False, encoding, lower=lower)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli")
    parser.add_argument("--encoding", choices=("packetaddr", "fixed"), default="packetaddr")
    args = parser.parse_args()
    main(args.cli, args.encoding)
