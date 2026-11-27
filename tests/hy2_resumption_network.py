#!/usr/bin/env python3
"""Observe Hysteria 2 TLS tickets at independently authenticated QUIC peers."""
import argparse
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile

from detour_network import exact, reserve
from dns_rule_support import nexus_process
def peer_line(peer):
    if not select.select([peer.stdout], [], [], 5)[0]:
        raise RuntimeError("timed out waiting for the Hysteria 2 peer")
    line = peer.stdout.readline().decode().strip()
    if not line:
        raise RuntimeError(f"Hysteria 2 peer exited with status {peer.poll()}")
    return line


def client_request(front, route, counter):
    with socket.create_connection(("127.0.0.1", front), timeout=5) as client:
        client.sendall(b"\x05\x01\x00")
        assert exact(client, 2) == b"\x05\x00"
        destinations = (b"\x01\x7f\x00\x00\x01", b"\x01\x7f\x00\x00\x02",
                        b"\x01\x7f\x00\x00\x03", b"\x01\x7f\x00\x00\x04")
        client.sendall(b"\x05\x01\x00" + destinations[route] + b"\x00\x50")
        assert exact(client, 10)[:2] == b"\x05\x00"
        payload = f"authenticated Hysteria 2 tunnel {counter}".encode()
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        assert exact(client, len(payload)) == payload
        assert client.recv(1) == b""


def verify(binary, peer_bin, require_resumption):
    with tempfile.TemporaryDirectory(prefix="nexus-hy2-resumption-") as temp:
        root = Path(temp)
        cert, key = root / "cert.pem", root / "key.pem"
        password = root / "password"
        password.write_text("test-password\n")
        password.chmod(0o600)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:prime256v1", "-noenc", "-keyout", key, "-out", cert,
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"],
                       check=True, capture_output=True)
        peer = subprocess.Popen([peer_bin, cert, key], stdout=subprocess.PIPE, bufsize=0,
                                env={**os.environ, "GODEBUG": "tlsmlkem=0"})
        try:
            ports = {}
            for _ in range(3):
                group, port = peer_line(peer).split()
                ports[group] = int(port)
            front = reserve()
            clients = (("ipv4", "127.0.0.1"), ("ipv6", "::1"), ("ipv4", "127.0.0.1"),
                       ("other-port", "127.0.0.1"))
            outbounds = []
            rule_sets = []
            route_rules = []
            for index, (group, host) in enumerate(clients):
                (root / f"rule-{index}.kdl").write_text(
                    f'schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.{index + 1}/32"\n')
                rule_sets.append(f'        rule{index} path="rule-{index}.kdl" format="kdl"')
                route_rules.append(f'- kind="rule-set" value="rule{index}" outbound="edge{index}"')
                outbounds.append(f'''outbound "edge{index}" type="hysteria2" {{
    server host="{host}" port={ports[group]}
    authentication {{ password-file "{password}"; }}
    tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}
}}
''')
            path = root / "config.kdl"
            path.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
{"".join(outbounds)}
routing {{
    rulesets {{
{chr(10).join(rule_sets)}
    }}
    rules {{
        {chr(10).join(route_rules)}
    }}
    final "edge0"
}}
''')
            with nexus_process(binary, path):
                for sequence, (route, resumes) in enumerate(((0, False), (0, True), (1, False), (1, True),
                                                             (2, False), (3, False))):
                    client_request(front, route, sequence)
                    status = peer_line(peer)
                    expect = require_resumption and resumes
                    assert status == f"auth group={clients[route][0]} resumed={str(expect).lower()} early=false", status
                    print(status, flush=True)
        finally:
            peer.terminate()
            peer.communicate(timeout=5)
    print("Hysteria 2 authenticated 1-RTT connections preserved ticket isolation and transferred application data")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("peer", type=Path)
    parser.add_argument("--off", action="store_true")
    args = parser.parse_args()
    verify(args.binary, args.peer, not args.off)
