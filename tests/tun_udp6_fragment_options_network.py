#!/usr/bin/env python3
"""Send independently encoded IPv6 UDP fragments through routed Linux TUN."""
import hashlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile

from dns_rule_support import nexus_process
from tailscale_endpoint_network import eventually, ip, line, process
from tun_external_fd_network import prepare_network

DEVICE = "nx-frag"
LOCAL = "2001:db8:2::1"
REMOTE = "2001:db8:1::2"
PORT = 18080


def udp_packet(source_port, payload):
    addresses = socket.inet_pton(socket.AF_INET6, LOCAL) + socket.inet_pton(socket.AF_INET6, REMOTE)
    length = len(payload) + 8
    udp = struct.pack("!4H", source_port, PORT, length, 0) + payload
    pseudo = addresses + struct.pack("!I3xB", length, 17)
    wire = pseudo + udp
    if len(wire) % 2:
        wire += b"\0"
    total = sum(word for (word,) in struct.iter_unpack("!H", wire))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    checksum = (~total & 65535) or 65535
    return addresses, udp[:6] + struct.pack("!H", checksum) + udp[8:]


def fragment(addresses, identification, offset, more, payload, *, hop=False, next_header=17):
    header = struct.pack("!BBHI", next_header, 0, offset | int(more), identification)
    options = bytes([44, 0, 1, 4, 0, 0, 0, 0]) if hop else b""
    content = options + header + payload
    return struct.pack("!IHBB", 0x60000000, len(content), 0 if hop else 44, 64) + addresses + content


def exchange():
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client, \
            socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw:
        client.bind((LOCAL, 0))
        raw.bind((LOCAL, 0))
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, DEVICE.encode() + b"\0")
        client.settimeout(2)

        def send(*packets):
            for item in packets:
                assert raw.sendto(item, (REMOTE, 0)) == len(item)

        def reply(payload):
            data, source = client.recvfrom(4096)
            assert hashlib.sha256(payload).digest() == data and source[:2] == (REMOTE, PORT), (len(data), source)

        payload = b"udp-fragment-with-options:" * 70 + b"!"
        addresses, udp = udp_packet(client.getsockname()[1], payload)
        destination = bytes([17, 0, 1, 4, 0, 0, 0, 0])
        for ident, content, next_header, hop in (
            (11, udp, 17, False),
            (12, udp, 17, True),
            (13, destination + udp, 60, False),
            (14, destination + udp, 60, True),
        ):
            # Deliver the suffix first. Only the first fragment contributes its
            # extension headers to the reassembled packet.
            send(fragment(addresses, ident, 1024, False, content[1024:], next_header=next_header),
                 fragment(addresses, ident, 0, True, content[:1024], hop=hop, next_header=next_header))
            try:
                reply(payload)
            except TimeoutError as error:
                raise AssertionError(f"no reply for fragment case {ident}") from error

        data = b"atomic UDP"
        _, udp = udp_packet(client.getsockname()[1], data)
        send(fragment(addresses, 15, 0, False, destination + udp, hop=True, next_header=60))
        reply(data)

        packet = destination + udp
        send(fragment(addresses, 16, 0, True, packet[:8], hop=True, next_header=60),
             fragment(addresses, 16, 8, False, packet[8:], next_header=60))
        send(fragment(addresses, 17, 0, True, packet[:16], hop=True, next_header=60),
             fragment(addresses, 17, 8, False, packet[8:], next_header=60),
             fragment(addresses, 17, 16, False, packet[16:], next_header=60))
        client.settimeout(.35)
        try:
            raise AssertionError(f"invalid fragments were forwarded: {client.recv(4096)!r}")
        except TimeoutError:
            pass
        client.settimeout(2)
        send(fragment(addresses, 18, 0, False, packet, hop=True, next_header=60))
        reply(data)


def run(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-tun-ipv6-fragments-") as temp, \
            process(["unshare", "-n", "sleep", "20"]) as child:
        parent_ns = os.stat("/proc/self/ns/net").st_ino
        eventually(lambda: os.stat(f"/proc/{child.pid}/ns/net").st_ino != parent_ns)
        route = prepare_network(child.pid)
        config = Path(temp) / "config.kdl"
        config.write_text(f'''schema-version 1
role "client"
inbound "tun" type="tun" {{
    interface-name "{DEVICE}"
    inet6-address "{LOCAL}/128"
    mtu 1400
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
        echo = Path(__file__).resolve()
        with process([*route, sys.executable, echo, "--echo"]) as origin:
            assert line(origin) == b"ready\n"
            with nexus_process(binary, config):
                ip("-6", "route", "add", f"{REMOTE}/128", "dev", DEVICE, "table", "610")
                ip("-6", "rule", "add", "from", f"{LOCAL}/128", "lookup", "610")
                exchange()
    print("IPv6 routed TUN reassembled UDP with Hop-by-Hop and Destination Options, rejected overlaps and incomplete headers")


if __name__ == "__main__":
    if sys.argv[1] == "--echo":
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as peer:
            peer.bind((REMOTE, PORT))
            print("ready", flush=True)
            while True:
                data, client = peer.recvfrom(4096)
                peer.sendto(hashlib.sha256(data).digest(), client)
    elif sys.argv[1] == "--namespace":
        run(sys.argv[2])
    else:
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--namespace", sys.argv[1]],
                       check=True, timeout=30)
