#!/usr/bin/env python3
"""Observe CONNECT-UDP TLS 1-RTT resumption on distinct named profiles."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import tempfile

from detour_network import reserve
from dns_rule_support import nexus_process, udp_client
from masque_network_selection import exchange
from tailscale_endpoint_network import line, process
from udp_bind_port_network import certificate


def verify(binary, fixture, enabled):
    with tempfile.TemporaryDirectory(prefix="nexus-masque-resumption-") as folder, ExitStack() as stack:
        root = Path(folder)
        certificate(root)
        token = root / "token"
        token.write_text("approved\n")
        token.chmod(0o600)
        servers = {}
        for host in ("127.0.0.1", "::1"):
            authority = f"[{host}]:0" if ":" in host else f"{host}:0"
            server = stack.enter_context(process([fixture, "serve-network", root / "cert", root / "key", authority],
                                                  env=dict(os.environ, NEXUS_TEST_MASQUE_RESUMPTION="1")))
            port = int(line(server).split(b":")[-1])
            servers[host] = server, port

        specs = ((0, "127.0.0.1"), (1, "::1"), (2, "127.0.0.1"))
        entries, edges, rules, ports = [], [], [], []
        for index, host in specs:
            ports.append(reserve())
            entries.append(f'''inbound "local{index}" type="socks5" {{
    listen host="127.0.0.1" port={ports[-1]}
    authentication "none"
}}''')
            edges.append(f'''outbound "edge{index}" type="masque" {{
    server host="{host}" port={servers[host][1]}
    authority "localhost"
    authentication {{ bearer-file "{token}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}''')
            rule = root / f"inbound-{index}.kdl"
            rule.write_text(f'schema-version 2\nkind "predicate"\nrule type="inbound" value="local{index}"\n')
            rules.append((f'        origin{index} path="{rule.name}" format="kdl"',
                          f'- rule-set="origin{index}" to="edge{index}"'))
        config = root / "nexus.kdl"
        config.write_text(f'''schema-version 1
role "client"
workers 2
{chr(10).join(entries)}
outbound "direct" type="direct"
{chr(10).join(edges)}
routing {{
    rulesets {{
{chr(10).join(rs for rs, _ in rules)}
    }}
    rules {{
        {chr(10).join(rr for _, rr in rules)}
    }}
    final "edge0"
}}
''')
        with nexus_process(binary, config, listeners=len(ports)):
            for index, warmed in ((0, False), (0, True), (1, False), (1, True), (2, False)):
                with udp_client(ports[index]) as association:
                    exchange(association)
                status = line(servers[specs[index][1]][0]).decode().strip()
                assert status == f"resumed={str(enabled and warmed).lower()} early=false", (index, status)
                print(index, status, flush=True)
    print("MASQUE issued authenticated CONNECT-UDP and preserved named profile ticket isolation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("peer", type=Path)
    parser.add_argument("--off", action="store_true")
    args = parser.parse_args()
    verify(args.binary.resolve(strict=True), args.peer.resolve(strict=True), not args.off)
