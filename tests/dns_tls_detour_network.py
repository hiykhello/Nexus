#!/usr/bin/env python3
"""Verify production DNS-over-TLS over a named stream detour."""
import argparse
import concurrent.futures
import socket
import tempfile
from pathlib import Path

from anytls_network import Origin
from detour_network import running
from dns_rule_support import free_port, nexus_process, stream_request
from dns_tls_network import DotServer
from udp_bind_port_network import certificate


def verify(binary, host, family):
    with tempfile.TemporaryDirectory(prefix="nexus-proxy-dot-") as directory:
        root = Path(directory)
        certificate(root)
        password = root / "password"
        password.write_text("dot-proxy-secret\n")
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
routing {{ default-outbound "direct"; }}
''')
        with DotServer(root, host, family) as dot:
            config = root / "front.kdl"
            source = f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "dns-proxy" type="trojan" {{
  server host="127.0.0.1" port={lower}
  authentication {{ password-file "{password}"; }}
  tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
dns {{
  server "upstream" type="tls" host="{host}" port={dot.port} server-name="dot.test" ca-file="{dot.cert}" detour="dns-proxy"
  final "upstream"
  strategy "ipv4_only"
  disable-cache #true
}}
routing {{ default-outbound "direct"; }}
'''
            config.write_text(source)
            with Origin(expected=3) as origin, nexus_process(binary, config):
                stream_request(front, origin.port, "offline.test", success=False)
                assert not dot.first_record, "offline detour contacted the TLS peer"
                with running([binary, "run", "--config", lower_config], lower, root / "lower.log"):
                    stream_request(front, origin.port, "online.test")
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pending:
                        first=pending.submit(stream_request,front,origin.port,"first.test")
                        assert dot.seen["first.test"].wait(2), dot.queries
                        stream_request(front,origin.port,"second.test")
                        first.result(timeout=3)
                    assert [entry[0] for entry in dot.wire_queries] == ["online.test","first.test","second.test"]
                    assert len({entry[1] for entry in dot.wire_queries}) == 1, dot.wire_queries
                    assert len({entry[2] for entry in dot.wire_queries}) == 3, dot.wire_queries
                    origin.wait()
            config.write_text(source.replace('server-name="dot.test"', 'server-name="wrong.test"'))
            with running([binary, "run", "--config", lower_config], lower, root / "lower.log"):
                with nexus_process(binary, config):
                    stream_request(front, 9, "wrong-identity.test", success=False)
            assert dot.queries == [(name, 1) for name in ("online.test","first.test","second.test")], dot.queries
    print(f"tls {host}: DoT through Trojan, offline failure, pipelined reuse and identity rejection passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nexus", type=Path)
    args = parser.parse_args()
    binary = args.nexus.resolve(strict=True)
    for host, family in (("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)):
        verify(binary, host, family)


if __name__ == "__main__":
    main()
