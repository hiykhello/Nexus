#!/usr/bin/env python3
"""Validate TUIC's new exporter authentication after TLS resumption."""
import argparse
from contextlib import ExitStack
from pathlib import Path
import tempfile
import time

from detour_network import reserve
from dns_rule_support import exact, nexus_process
from tailscale_endpoint_network import line, process
from tcp_proxy_outbounds_network import open_socks
from udp_bind_port_network import certificate


def verify(binary, fixture, enabled):
    with tempfile.TemporaryDirectory(prefix="nexus-tuic-resumption-") as folder, ExitStack() as stack:
        root = Path(folder)
        certificate(root)
        uuid, password = root / "uuid", root / "password"
        uuid.write_text("00112233-4455-6677-8899-aabbccddeeff\n")
        password.write_text("tuic-test\n")
        uuid.chmod(0o600)
        password.chmod(0o600)
        servers = {}
        for host, listen in (("127.0.0.1", "127.0.0.1:0"), ("::1", "[::1]:0")):
            server = stack.enter_context(process([fixture, root / "cert", root / "key", listen]))
            servers[host] = server, int(line(server).split(b":")[-1])

        specs = ((0, "127.0.0.1"), (1, "::1"), (2, "127.0.0.1"))
        entries, edges, rules, ports = [], [], [], []
        for index, host in specs:
            ports.append(reserve())
            entries.append(f'''inbound "local{index}" type="socks5" {{
    listen host="127.0.0.1" port={ports[-1]}
    authentication "none"
}}''')
            edges.append(f'''outbound "edge{index}" type="tuic" {{
    server host="{host}" port={servers[host][1]}
    idle-timeout-ms 400
    authentication {{ uuid-file "{uuid}"; password-file "{password}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}''')
            rule = root / f"inbound-{index}.kdl"
            rule.write_text(f'schema-version 2\nkind "predicate"\nrule type="inbound" value="local{index}"\n')
            rules.append((f'rule-set "origin{index}" path="{rule.name}" format="kdl"',
                          f'- kind="rule-set" value="origin{index}" outbound="edge{index}"'))
        config = root / "nexus.kdl"
        config.write_text(f'''schema-version 1
role "client"
{chr(10).join(entries)}
outbound "direct" type="direct"
{chr(10).join(edges)}
routing {{
    {chr(10).join(rs for rs, _ in rules)}
    rules {{
        {chr(10).join(rr for _, rr in rules)}
    }}
    default-outbound "edge0"
}}
''')
        with nexus_process(binary, config, listeners=len(ports)):
            for index, warmed in ((0, False), (0, True), (1, False), (1, True), (2, False)):
                if warmed:
                    time.sleep(1.1)
                payload = f"fresh TUIC authentication {index} / {warmed}".encode()
                with open_socks(ports[index], "127.0.0.1", 53) as client:
                    client.sendall(payload)
                    assert exact(client, len(payload)) == payload
                status = line(servers[specs[index][1]][0]).decode().strip()
                assert status == f"auth resumed={str(enabled and warmed).lower()} early=false", (index, status)
                print(index, status, flush=True)
    print("TUIC used the TLS exporter for each authenticated connection and isolated tickets between named profiles")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("peer", type=Path)
    parser.add_argument("--off", action="store_true")
    args = parser.parse_args()
    verify(args.binary.resolve(strict=True), args.peer.resolve(strict=True), not args.off)
