#!/usr/bin/env python3
"""Verify AnyTLS payload-byte limits through TCP relay and native UDP targets."""

from pathlib import Path
import subprocess
import sys
import tempfile
import time

from anytls_network import Origin
from anytls_test_peer import Peer, address, datagram
from dns_rule_support import Echo, free_port, nexus_process
from principal_limits_network import REVISION, shadowsocks, tls_peer, usage
from proxy_listener_reload_network import reload
from udp_bind_port_network import certificate


def open_udp(peer):
    stream = peer.open("sp.v2.udp-over-tcp.arpa", 0, b"\x00" + address("0.0.0.0", 0))
    peer.ack(stream)
    return stream


def send_udp(peer, stream, origin, payload, accepted=True, forwarded=False):
    seen = len(origin.received)
    peer.send(stream, datagram("127.0.0.1", origin.port, payload))
    peer.socket.settimeout(2 if accepted else .2)
    try:
        reply = peer.read_datagram(stream)
    except TimeoutError:
        if accepted:
            raise
        assert origin.received[seen:] == ([payload] if forwarded else [])
    else:
        assert accepted and reply[3] == payload
    finally:
        peer.socket.settimeout(5)


def check(binary, root):
    front = free_port()
    path = root / "server.kdl"
    control = root / "control"

    def publish(quota):
        replacement = path.with_suffix(".candidate")
        replacement.write_text(f'''schema-version 1
role "server"
workers 2
shutdown-grace-ms 10000
control socket="{control}"
inbound "edge" type="anytls" {{
 listen host="127.0.0.1" port={front}
 authentication {{ user "alice" password-file="{root / 'alice'}"; user "bob" password-file="{root / 'bob'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
 user-limits {{ user "alice" byte-quota={quota}; user "bob" bytes-per-second=100 burst-bytes=8; }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        replacement.replace(path)

    publish(12)
    with nexus_process(binary, path) as running, Echo() as udp, Origin(idle_timeout=8) as origin:
        with Peer(root, front, "alice") as alice:
            tcp = alice.open("127.0.0.1", origin.port, b"abc")
            alice.ack(tcp)
            assert alice.read(tcp, 3) == b"abc"
            flow = open_udp(alice)
            send_udp(alice, flow, udp, b"def")
            usage(binary, control, 0, "alice", upload=6, download=6, byte_limit_denials=0)
            send_udp(alice, flow, udp, b"rejected", accepted=False)
            usage(binary, control, 0, "alice", upload=6, download=6, byte_limit_denials=1)
            publish(21)
            assert reload(running) == 2
            send_udp(alice, flow, udp, b"gh")
            alice.finish(flow)
            alice.finish(tcp)
            with Peer(root, front, "alice") as next_alice:
                next_flow = open_udp(next_alice)
                send_udp(next_alice, next_flow, udp, b"ij")
                usage(binary, control, 0, "alice", upload=10, download=10, byte_limit_denials=1)
                send_udp(next_alice, next_flow, udp, b"k", accepted=False, forwarded=True)
                usage(binary, control, 0, "alice", upload=11, download=10, byte_limit_denials=2)
                send_udp(next_alice, next_flow, udp, b"again-rejected", accepted=False)
                next_alice.finish(next_flow)
        with Peer(root, front, "bob") as bob:
            payload = bytes(range(20))
            started = time.monotonic()
            tcp = bob.open("127.0.0.1", origin.port, payload)
            bob.ack(tcp)
            assert bob.read(tcp, len(payload)) == payload
            assert time.monotonic() - started >= .27
            bob.finish(tcp)
            flow = open_udp(bob)
            send_udp(bob, flow, udp, b"123456789", accepted=False)
            send_udp(bob, flow, udp, b"")
            usage(binary, control, 0, "bob", upload=20, download=20)
            bob.finish(flow)


if __name__ == "__main__":
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-principal-bytes-") as folder:
        root = Path(folder)
        for user in ("alice", "bob"):
            secret = root / user
            secret.write_text(user + "\n")
            secret.chmod(0o600)
        certificate(root)
        if "--ss" in sys.argv[2:]:
            version = subprocess.check_output(["sing-box", "version"], text=True)
            assert f"Revision: {REVISION}" in version
            for ordered in (False, True):
                shadowsocks(binary, root, byte_limits=True, ordered=ordered)
                print(f"SS-2022 shared TCP/native UDP quota passed, ordered={ordered}", flush=True)
        elif "--quic" in sys.argv[2:] or "--tls" in sys.argv[2:]:
            version = subprocess.check_output(["sing-box", "version"], text=True)
            assert f"Revision: {REVISION}" in version
            cases = (("hysteria2", False), ("tuic", False), ("tuic", True)) if "--quic" in sys.argv[2:] else (
                ("trojan", False), ("vless", False), ("vless-grpc", False))
            for protocol, over_stream in cases:
                tls_peer(binary, root, protocol, byte_limits=True, udp_over_stream=over_stream)
                print(f"{protocol} shared TCP/UDP quota passed, UDP over stream={over_stream}", flush=True)
        else:
            check(binary, root)
            print("AnyTLS shared TCP/UDP byte quota, reload, partial pacing and whole-datagram rejection passed")
