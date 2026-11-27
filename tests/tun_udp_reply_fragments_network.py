#!/usr/bin/env python3
"""Verify outbound TUN reply fragments and reassembly with the Linux UDP stack."""
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading

from dns_rule_support import nexus_process
from tailscale_endpoint_network import eventually, ip, line, process
from tun_external_fd_network import prepare_network

DEVICE = "nx-reply"
PORT = 18086
PAYLOAD = bytes(range(255)) * 15 + b"fragmented response"
TARGETS = (
    (socket.AF_INET, "-4", "192.0.2.2", "198.51.100.1", 32),
    (socket.AF_INET6, "-6", "2001:db8:1::2", "2001:db8:2::1", 128),
)


def distinct_fragments(capture, family, source):
    source = socket.inet_pton(family, source)
    pieces = {}
    expected_id = None
    sock_timeout = capture.gettimeout()
    try:
        capture.settimeout(.5)
        while True:
            wire = capture.recv(65535)
            if family == socket.AF_INET:
                if len(wire) < 20 or wire[0] >> 4 != 4 or wire[12:16] != source or wire[9] != 17:
                    continue
                ident, flags = struct.unpack_from("!HH", wire, 4)
                offset, more, overhead = (flags & 0x1fff) * 8, flags & 0x2000, 20
            else:
                if len(wire) < 48 or wire[0] >> 4 != 6 or wire[8:24] != source or wire[6] != 44:
                    continue
                assert wire[40] == 17
                flags, ident = struct.unpack_from("!HI", wire, 42)
                offset, more, overhead = flags & 0xfff8, flags & 1, 48
            if not offset and not more:
                continue
            assert len(wire) <= 1280
            if expected_id is None:
                expected_id = ident
            assert ident == expected_id
            pieces[offset] = wire[overhead:]
            if not more:
                break
        offsets = sorted(pieces)
        assert len(offsets) >= 3 and offsets[0] == 0
        assert all(left + len(pieces[left]) == right for left, right in zip(offsets, offsets[1:]))
        assert b"".join(pieces[offset] for offset in offsets)[8:] == PAYLOAD
    finally:
        capture.settimeout(sock_timeout)


def check_client(expect, family, remote, local):
    with socket.socket(family, socket.SOCK_DGRAM) as client, \
            socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3)) as capture:
        capture.bind((DEVICE, 3))
        client.settimeout(1.0)
        client.bind((local, 0))
        client.connect((remote, PORT))
        client.send(b"large")
        try:
            reply = client.recv(65535)
        except TimeoutError:
            assert not expect, f"no fragmented {family.name} reply"
        else:
            assert expect and reply == PAYLOAD, (family, len(reply))
            distinct_fragments(capture, family, remote)
        client.send(b"small")
        assert client.recv(32) == b"small"


def verify(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-tun-reply-fragments-") as temp, \
            process(["unshare", "-n", "sleep", "25"]) as child:
        parent_ns = os.stat("/proc/self/ns/net").st_ino
        eventually(lambda: os.stat(f"/proc/{child.pid}/ns/net").st_ino != parent_ns)
        route = prepare_network(child.pid)
        with process([*route, sys.executable, Path(__file__).resolve(), "--echo"]) as far:
            assert line(far) == b"ready\n"
            for expect in (False, True):
                config = Path(temp) / "cfg.kdl"
                enabled = "udp-reply-fragment #true" if expect else ""
                config.write_text(f'''schema-version 1
role "client"
inbound "tun" type="tun" {{
    interface-name "{DEVICE}"
    inet4-address "198.51.100.1/32"
    inet6-address "2001:db8:2::1/128"
    mtu 1280
    {enabled}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
                with nexus_process(binary, config):
                    for family, flag, remote, local, prefix in TARGETS:
                        ip(flag, "route", "add", f"{remote}/{prefix}", "dev", DEVICE, "table", "610")
                        ip(flag, "rule", "add", "from", f"{local}/{prefix}", "lookup", "610")
                        try:
                            check_client(expect, family, remote, local)
                        finally:
                            ip(flag, "rule", "del", "from", f"{local}/{prefix}", "lookup", "610")
    print("Routed TUN IPv4 and IPv6 returned captured UDP fragments with full kernel reassembly and default oversize drops")


def echo():
    def serve(peer):
        with peer:
            while True:
                data, source = peer.recvfrom(2048)
                peer.sendto(PAYLOAD if data == b"large" else data, source)

    for family, _, remote, _, _ in TARGETS:
        peer = socket.socket(family, socket.SOCK_DGRAM)
        peer.bind((remote, PORT))
        threading.Thread(target=serve, args=(peer,), daemon=True).start()
    print("ready", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    if sys.argv[1] == "--echo":
        echo()
    elif sys.argv[1] == "--namespace":
        verify(sys.argv[2])
    else:
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--namespace", sys.argv[1]],
                       check=True, timeout=30)
