#!/usr/bin/env python3
"""Verify that DNS message policy uses the ingress of the business packet."""
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile

from dns_rule_support import DnsPeer, dns_request, free_port, nexus_process, question, wire_name
from tailscale_endpoint_network import ip

NAME = "nx-dns"
TARGETS = (
    ("-4", socket.AF_INET, "198.51.100.8", "198.18.0.1", 32, 1),
    ("-6", socket.AF_INET6, "2001:db8:cafe::8", "2001:db8:aaaa::1", 128, 28),
)


def verify(cli):
    ip("link", "set", "lo", "up")
    with tempfile.TemporaryDirectory(prefix="nexus-dns-interface-") as temp, DnsPeer() as origin:
        root = Path(temp)
        port = free_port()
        (root / "via-tun.kdl").write_text(f'''schema-version 2
kind "predicate"
rule type="source-interface" value="{NAME}"
''')
        (root / "target.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="port" value="53"\n')
        config = root / "config.kdl"
        config.write_text(f'''schema-version 1
role "client"
inbound "tun" type="tun" {{
    interface-name "{NAME}"
    inet4-address "198.18.0.1/32"
    inet6-address "2001:db8:aaaa::1/128"
}}
outbound "direct" type="direct"
dns {{
    listen host="127.0.0.1" port={port}
    server "answer" type="udp" host="127.0.0.1" port={origin.port}
    rule domain="interface-a.test" source-interface="{NAME}" action="route" server="answer"
    rule domain="interface-b.test" rule-set="iface" action="route" server="answer"
    rule-set "iface" path="via-tun.kdl" format="kdl"
    rule source-interface="wrong" invert=#true action="route" server="answer"
    rule action="reject"
    final "answer"
}}
routing {{
    rule-set "target" path="target.kdl" format="kdl"
    tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{
        rule action="hijack-dns" rule-set="target"
        rule action="reject"
    }}
    default-outbound "direct"
}}
''')
        with nexus_process(cli, config):
            for flag, family, target, local, prefix, kind in TARGETS:
                ip(flag, "route", "add", f"{target}/{prefix}", "dev", NAME, "src", local)
                with socket.socket(family, socket.SOCK_DGRAM) as client:
                    client.settimeout(3)
                    for index, name in enumerate(("interface-a.test", "interface-b.test", "inverted.test")):
                        ident = 0x6123 + index
                        query = struct.pack("!6H", ident, 0x100, 1, 0, 0, 0)
                        query += wire_name(name) + struct.pack("!HH", kind, 1)
                        client.sendto(query, (target, 53))
                        reply, source = client.recvfrom(4096)
                        assert source[:2] == (target, 53), source
                        identifier, flags, questions, answers = struct.unpack_from("!4H", reply)
                        assert (identifier, flags & 15, questions, answers) == (ident, 0, 1, 1), reply.hex()
                        assert question(reply)[:2] == (name, kind)
                        assert (name, kind, "udp") in origin.seen
            for transport in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                for name in ("interface-a.test", "interface-b.test", "inverted.test"):
                    assert dns_request(port, name, transport) == (5, None)
            assert len(origin.seen) == 6, origin.seen
    print("DNS interface and rule-set predicates matched routed TUN IPv4/IPv6; unknown source remained unknown on listener UDP/TCP")


if __name__ == "__main__":
    if sys.argv[1] == "--namespace":
        verify(sys.argv[2])
    else:
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--namespace", sys.argv[1]],
                       check=True, timeout=35)
