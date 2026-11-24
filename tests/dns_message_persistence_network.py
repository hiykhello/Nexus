#!/usr/bin/env python3
"""Restore a private DNS message checkpoint without extending answer TTL."""

import errno
from pathlib import Path
import secrets
import socket
import struct
import sys
import tempfile
import time

from dns_rule_support import DnsPeer, bind_same_port, free_port, nexus_process, question, wire_name
from proxy_listener_reload_network import reload


class Peer(DnsPeer):
    def __init__(self, ipv6=False, answer="127.0.0.1"):
        super().__init__(ipv6=ipv6)
        self.answer = socket.inet_aton(answer)

    def reply(self, packet, transport):
        reply = super().reply(packet, transport)
        if reply is None:
            return None
        end = question(reply)[2]
        return reply[:end + 6] + struct.pack("!I", 8) + reply[end + 10:-4] + self.answer


def query_from(client, port, identifier, answer):
    client.settimeout(3)
    request = struct.pack("!6H", identifier, 0x100, 1, 0, 0, 0) + wire_name("persist.test") + b"\0\1\0\1"
    client.sendto(request, ("127.0.0.1", port))
    reply = client.recv(2048)
    assert struct.unpack_from("!4H", reply) == (identifier, 0x8180, 1, 1), reply
    assert reply[-4:] == answer, reply
    return struct.unpack_from("!I", reply, question(reply)[2] + 6)[0]


def query(port, identifier):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        return query_from(client, port, identifier, socket.inet_aton("127.0.0.1"))


def checkpoint_listener_port():
    # Avoid assigning a checkpoint listener's port to a local client
    # connection while the listener is down between process generations.
    ephemeral_start = int(Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()[0])
    for _ in range(256):
        port = 1024 + secrets.randbelow(ephemeral_start - 1024)
        try:
            _, (tcp, udp) = bind_same_port((
                (socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1"),
                (socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1"),
            ), port)
        except OSError as error:
            if error.errno != errno.EADDRINUSE:
                raise
        else:
            with tcp, udp:
                return port
    raise RuntimeError("no available DNS checkpoint listener port")


def check(binary, root, peer, alternate, transport, check_expiry):
    front, dns_port = free_port(), checkpoint_listener_port()
    directory = root / "cache"
    directory.mkdir(mode=0o700)
    snapshot = directory / "messages.cache"
    config = root / "proxy.kdl"
    source = f'''schema-version 1
role "client"
inbound "main" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
dns {{
   listen host="127.0.0.1" port={dns_port}
   message-cache-directory "{directory}"
   server "dns" type="{transport}" host="{peer.host}" port={peer.port}
   final "dns"
}}
'''
    config.write_text(source)
    with nexus_process(binary, config):
        assert query(dns_port, 51) == 8
    assert snapshot.stat().st_mode & 0o777 == 0o600
    first_checkpoint = snapshot.read_bytes()
    assert first_checkpoint.startswith(b"NXDNS2")
    assert len(peer.seen) == 1
    time.sleep(1.1)

    with nexus_process(binary, config) as process:
        assert 0 < query(dns_port, 52) <= 6
        assert len(peer.seen) == 1
        reload(process)
        assert 0 < query(dns_port, 53) <= 6
        assert len(peer.seen) == 1
        config.write_text(source.replace(f"port={peer.port}", f"port={alternate.port}"))
        reload(process)
        assert query(dns_port, 54) == 8
        assert len(alternate.seen) == 1
    assert snapshot.read_bytes().startswith(b"NXDNS2")

    snapshot.write_bytes(first_checkpoint[:-1])
    config.write_text(source)
    with nexus_process(binary, config):
        assert query(dns_port, 55) == 8
        assert len(peer.seen) == 2

    if check_expiry:
        snapshot.write_bytes(first_checkpoint)
        time.sleep(8)
        with nexus_process(binary, config):
            assert query(dns_port, 56) == 8
            assert len(peer.seen) == 3


def check_views(binary, root, first, second):
    directory = root / "cache"
    directory.mkdir(mode=0o700)
    front, dns_port = free_port(), checkpoint_listener_port()
    config = root / "proxy.kdl"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as selected, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fallback:
        selected.bind(("127.0.0.1", 0))
        fallback.bind(("127.0.0.1", 0))
        source_port = selected.getsockname()[1]
        # The two clients send an identical question. The policy routes by
        # source, so restoring a row into the wrong resolver can leak a view.
        source = f'''schema-version 1
role "client"
inbound "main" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
dns {{
   listen host="127.0.0.1" port={dns_port}
   message-cache-directory "{directory}"
   server "first" type="udp" host="{first.host}" port={first.port}
   server "second" type="tcp" host="{second.host}" port={second.port}
   rule domain="persist.test" source-port={source_port} server="second"
   final "first"
}}
'''
        config.write_text(source)
        with nexus_process(binary, config):
            assert query_from(selected, dns_port, 61, second.answer) == 8
            assert query_from(fallback, dns_port, 62, first.answer) == 8
        assert len(first.seen) == len(second.seen) == 1
        snapshot = directory / "messages.cache"
        original = snapshot.read_bytes()
        assert original.startswith(b"NXDNS2")
        with nexus_process(binary, config) as process:
            assert 0 < query_from(fallback, dns_port, 63, first.answer) < 8
            assert 0 < query_from(selected, dns_port, 64, second.answer) < 8
            assert len(first.seen) == len(second.seen) == 1
            reload(process)
            assert 0 < query_from(selected, dns_port, 65, second.answer) < 8
            assert len(second.seen) == 1
            # Keep the fallback upstream the same. The changed policy must
            # still discard its previous cache for both live and cold loads.
            changed = source.replace(f"source-port={source_port}", f"source-port={fallback.getsockname()[1]}")
            config.write_text(changed)
            reload(process)
            assert query_from(selected, dns_port, 66, first.answer) == 8
            assert query_from(fallback, dns_port, 67, second.answer) == 8
            assert len(first.seen) == len(second.seen) == 2
        snapshot.write_bytes(original)
        with nexus_process(binary, config):
            assert query_from(selected, dns_port, 68, first.answer) == 8
            assert query_from(fallback, dns_port, 69, second.answer) == 8
        assert len(first.seen) == len(second.seen) == 3


if __name__ == "__main__":
    cli = Path(sys.argv[1]).resolve(strict=True)
    for protocol, ipv6 in (("udp", False), ("tcp", True)):
        with tempfile.TemporaryDirectory(prefix="nexus-dns-cache-state-") as folder, \
                Peer(ipv6=ipv6) as first, Peer(ipv6=ipv6) as second:
            check(cli, Path(folder), first, second, protocol, check_expiry=not ipv6)
        print(f"DNS checkpoint, restored TTL, reload and damaged snapshot passed over {protocol} IPv{6 if ipv6 else 4}")

    with tempfile.TemporaryDirectory(prefix="nexus-dns-cache-views-") as folder, \
            Peer(answer="192.0.2.1") as first, Peer(ipv6=True, answer="192.0.2.2") as second:
        check_views(cli, Path(folder), first, second)
    print("DNS checkpoint preserved two source-selected resolver views and isolated policy changes")
