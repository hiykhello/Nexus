#!/usr/bin/env python3
"""Verify TCP DNS interception uses true source metadata and preserves DNS framing."""
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from detour_network import exact
from dns_rule_support import DnsPeer, nexus_process, question, wire_name
from tailscale_endpoint_network import ip

DEVICE = "nx-tcp-dns"
TARGETS = (
    ("-4", socket.AF_INET, "198.51.100.8", "198.18.0.1", 32, 1),
    ("-6", socket.AF_INET6, "2001:db8:cafe::8", "2001:db8:aaaa::1", 128, 28),
)


def query(ident, name, kind):
    return struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + wire_name(name) + struct.pack("!HH", kind, 1)


def frame(wire):
    return struct.pack("!H", len(wire)) + wire


def check_stream(family, target, kind):
    with socket.socket(family) as stream:
        stream.settimeout(4)
        stream.connect((target, 53))
        questions = (
            (0x1234, "valid.test", kind, 0),
            (0x1235, "denied.test", kind, 5),
            (0x1236, "again.test", kind, 0),
        )
        first, *remaining = [frame(query(ident, name, kind)) for ident, name, kind, _ in questions]
        stream.sendall(first[:1])
        stream.sendall(first[1:] + b"".join(remaining))
        stream.shutdown(socket.SHUT_WR)
        for ident, name, kind, rcode in questions:
            length, = struct.unpack("!H", exact(stream, 2))
            reply = exact(stream, length)
            received, flags, questions, answers = struct.unpack_from("!4H", reply)
            assert (received, flags & 15, questions, answers) == (ident, rcode, 1, int(rcode == 0)), reply.hex()
            assert question(reply)[:2] == (name, kind)
        assert stream.recv(1) == b""


def run(cli):
    ip("link", "set", "lo", "up")
    with tempfile.TemporaryDirectory(prefix="nexus-tun-tcp-dns-") as temp, DnsPeer() as peer:
        root = Path(temp)
        path = root / "config.kdl"
        (root / "target.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="port" value="53"\n')
        path.write_text(f'''schema-version 1
role "client"
inbound "tun" type="tun" {{
    interface-name "{DEVICE}"
    inet4-address "198.18.0.1/32"
    inet6-address "2001:db8:aaaa::1/128"
    dns-hijack-tcp #true
}}
outbound "direct" type="direct"
dns {{
    server "upstream" type="udp" host="127.0.0.1" port={peer.port}
    rule domain="denied.test" action="reject"
    rule network="tcp" source-interface="{DEVICE}" action="route" server="upstream"
    rule action="reject"
    final "upstream"
}}
routing {{
    rule-set "target" path="target.kdl" format="kdl"
    tcp-program sniff-timeout-ms=150 unknown="skip" {{
        rule action="sniff" rule-set="target"
        rule action="hijack-dns" rule-set="target"
        rule action="reject"
    }}
    default-outbound "direct"
}}
''')
        if "--explain" in sys.argv:
            explained = subprocess.run([cli, "rule", "explain", path, "tun", "tcp", "198.51.100.8:53",
                                        "protocol=dns", "source-interface=nx-tcp-dns"],
                                       check=True, capture_output=True, text=True, timeout=3).stdout
            assert any(line.endswith("hijack-dns") for line in explained.splitlines()), explained
        with nexus_process(cli, path):
            for flag, family, target, local, prefix, kind in TARGETS:
                ip(flag, "route", "add", f"{target}/{prefix}", "dev", DEVICE, "src", local)
                check_stream(family, target, kind)
        assert peer.seen == [(name, kind, "udp") for kind in (1, 28) for name in ("valid.test", "again.test")], peer.seen
    print("Routed TUN TCP DNS passed IPv4/IPv6, prefetched and pipelined frames, ingress matching, and graceful EOF")


if __name__ == "__main__":
    if sys.argv[1] == "--namespace":
        run(sys.argv[2])
    else:
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--namespace", sys.argv[1], *sys.argv[2:]],
                       check=True, timeout=25)
