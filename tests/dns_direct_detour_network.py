#!/usr/bin/env python3
"""Exercise explicit direct dial settings on encrypted DNS sockets."""
import argparse
import contextlib
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from detour_network import running
from dial_namespace_protect_network import broker, namespace_cookie
from dns_encrypted_network import config_text, peer, query
from dns_rule_support import DnsPeer, free_port
from dns_tls_network import DotServer, write_config


@contextlib.contextmanager
def upstream(fixture, root, protocol, host):
    if protocol == "tls":
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with DotServer(root, host, family) as dot:
            yield dot.port, dot.cert, dot
    else:
        with peer(fixture, root, protocol, host) as (port, cert, event):
            yield port, cert, event


def verify(binary, fixture, protocol, host, fast_open=False):
    with tempfile.TemporaryDirectory(prefix="nexus-dns-direct-") as directory, DnsPeer() as bootstrap:
        root = Path(directory)
        config = root / "nexus.kdl"
        front, listen = free_port(), free_port()
        with upstream(fixture, root, protocol, host) as (port, cert, observation):
            if protocol == "tls":
                write_config(config, observation, front, listen)
                source = config.read_text().replace('outbounds { direct "direct"; }', 'outbound "egress" type="direct"')
                source = source.replace('final "direct"', 'final "egress"')
                source = source.replace(f'ca-file="{cert}"', f'ca-file="{cert}" detour="egress"')
                source = source.replace('final "protected"', 'disable-cache #true\n    final "protected"')
            else:
                source = config_text(protocol, front, listen, host, port, cert, bootstrap.port)
                source = source.replace('outbound "direct"', 'outbound "egress"').replace(
                    'final "direct"', 'final "egress"')
                source = source.replace('bind-interface="lo"', 'detour="egress"')
            protect = root / "protect.sock"
            direct = 'outbound "egress" type="direct"'
            tfo = "tcp-fast-open #true;" if fast_open else ""
            source = source.replace(direct, direct + f' {{ protect-path "{protect}"; bind-interface "lo"; {tfo} }}')

            def command(label):
                start = [binary, "run", "--config", config]
                if fast_open:
                    start = ["strace", "-D", "-f", "-qq", "-e", "trace=sendto", "-s", "0",
                             "-o", root / f"{label}.trace", *start]
                return start

            with socket.socket() as local:
                cookie = namespace_cookie(local)
            kind = socket.SOCK_DGRAM if protocol == "quic" else socket.SOCK_STREAM
            with broker(protect, "ack") as calls:
                config.write_text(source.replace('detour="egress"', ''))
                with running(command("implicit"), front, root / "implicit.log"):
                    query(listen, "implicit.test")
                assert not calls, calls

                config.write_text(source)
                with running(command("explicit"), front, root / "explicit.log"):
                    query(listen, "explicit.test")
                assert calls == [(kind, cookie, 0)], calls
                if fast_open:
                    assert "MSG_FASTOPEN" not in (root / "implicit.trace").read_text()
                    assert "MSG_FASTOPEN" in (root / "explicit.trace").read_text()

            with broker(protect, "reject") as calls:
                with running([binary, "run", "--config", config], front, root / "rejected.log"):
                    query(listen, "denied.test", code=2)
                assert calls == [(kind, cookie, 0)], calls
            with broker(protect, "hold") as calls:
                config.write_text(source.replace(f'protect-path "{protect}";',
                    f'protect-path "{protect}"; connect-timeout-ms 75;'))
                with running([binary, "run", "--config", config], front, root / "deadline.log"):
                    started = time.monotonic()
                    query(listen, "deadline.test", code=2)
                    assert time.monotonic() - started < 1.5
                assert calls == [(kind, cookie, 0)], calls
            if protocol != "tls":
                assert observation().split()[:2] == ["request", "implicit.test"]
                assert observation().split()[:2] == ["request", "explicit.test"]
            else:
                assert observation.queries == [("implicit.test", 1), ("explicit.test", 1)]

            config.write_text(source.replace('detour="egress"', 'detour="missing"'))
            rejected = subprocess.run([binary, "run", "--config", config], timeout=3, capture_output=True)
            assert rejected.returncode and b"encrypted DNS detour must name a direct or proxy outbound" in rejected.stderr
            config.write_text(source.replace('detour="egress"', 'detour="egress" bind-interface="lo"'))
            rejected = subprocess.run([binary, "run", "--config", config], timeout=3, capture_output=True)
            assert rejected.returncode and b"without a separate bind-interface" in rejected.stderr
    suffix = " and explicit TCP Fast Open" if fast_open else ""
    print(f"{protocol} {host}: named direct protect, rejection, deadline and legacy isolation{suffix} passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nexus", type=Path)
    parser.add_argument("peer", type=Path)
    parser.add_argument("--tcp-fast-open", action="store_true")
    args = parser.parse_args()
    for protocol in (("tls", "h1", "h2") if args.tcp_fast_open else ("tls", "h1", "h2", "quic")):
        for host in ("127.0.0.1", "::1"):
            verify(args.nexus.resolve(strict=True), args.peer.resolve(strict=True), protocol, host, args.tcp_fast_open)


if __name__ == "__main__":
    main()
