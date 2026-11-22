#!/usr/bin/env python3
"""Check ordered TCP sniff/replay and UDP/DNS on one AnyTLS connection."""
import socket
import struct
import sys
import tempfile
from pathlib import Path

from anytls_test_peer import Peer, address, datagram
from dns_rule_support import DnsPeer, Echo, free_port, nexus_process, question, wire_name
from udp_bind_port_network import certificate

PASSWORD = "anytls-ordered-test"


def verify(cli, root, dns, origin):
    front = free_port()
    intercept = free_port()
    (root / "dns-port.kdl").write_text(f'schema-version 2\nkind "predicate"\nrule type="port" value="{intercept}"\n')
    (root / "blocked.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="drop.test"\n')
    config = root / "config.kdl"
    config.write_text(f'''schema-version 1
role "server"
inbound "edge" type="anytls" {{
    listen host="127.0.0.1" port={front}
    authentication {{ user "test" password-file="{root / 'password'}"; }}
    tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
}}
dns {{
    server "answer" type="udp" host="127.0.0.1" port={dns.port}
    server "other" type="udp" host="127.0.0.1" port=9
    rule domain-suffix="test" network="udp" inbound="edge" auth-user="test" server="answer"
    final "other"
}}
outbound "direct" type="direct"
routing {{
    rule-set "dns-port" path="dns-port.kdl" format="kdl"
    rule-set "blocked" path="blocked.kdl" format="kdl"
    tcp-program sniff-timeout-ms=200 udp=#true unknown="skip" {{
        rule action="hijack-dns" rule-set="dns-port"
        rule action="sniff"
        rule action="reject" rule-set="blocked" domain-source="sniffed"
        rule action="route" outbound="direct"
    }}
    default-outbound "direct"
}}
''')
    with nexus_process(cli, config), Peer(root, front, PASSWORD) as peer:
        denied = b"GET / HTTP/1.1\r\nHost: drop.test\r\n\r\n"
        allowed = b"GET / HTTP/1.1\r\nHost: allow.test\r\n\r\n"
        rejected = peer.open("127.0.0.1", origin.port, denied, fragmented=True)
        admitted = peer.open("::1", origin.port, allowed, fragmented=True)
        peer.ack(rejected, accepted=False)
        peer.ack(admitted)
        assert peer.read(admitted, len(allowed)) == allowed
        assert origin.accepted == [socket.AF_INET6], origin.accepted

        initial = b"\0" + address("0.0.0.0", 0)
        udp = peer.open("sp.v2.udp-over-tcp.arpa", 0, initial, fragmented=True)
        peer.ack(udp)
        for host, tag in (("127.0.0.1", 0), ("::1", 1)):
            data = b"after-reject" if tag else b""
            peer.send(udp, datagram(host, origin.port, data), fragmented=True)
            family = socket.AF_INET if tag == 0 else socket.AF_INET6
            assert peer.read_datagram(udp) == (tag, socket.inet_pton(family, host), origin.port, data)
        query = struct.pack("!HHHHHH", 0xA817, 0x100, 1, 0, 0, 0)
        query += wire_name("intercept.test") + struct.pack("!HH", 1, 1)
        peer.send(udp, datagram("::1", intercept, query))
        tag, host, port, reply = peer.read_datagram(udp)
        assert (tag, host, port) == (1, socket.inet_pton(socket.AF_INET6, "::1"), intercept)
        identifier, flags, questions, answers = struct.unpack_from("!4H", reply)
        assert (identifier, flags & 15, questions, answers) == (0xA817, 0, 1, 1)
        assert question(reply)[:2] == ("intercept.test", 1)
        assert ("intercept.test", 1, "udp") in dns.seen
    print("AnyTLS ordered TCP sniff, exact replay and sibling isolation, dual-stack UoT and DNS hijack passed")


def main(cli):
    with tempfile.TemporaryDirectory(prefix="nexus-anytls-ordered-") as temp, DnsPeer() as dns, Echo() as origin:
        root = Path(temp)
        certificate(root)
        (root / "key").chmod(0o600)
        (root / "password").write_text(PASSWORD)
        (root / "password").chmod(0o600)
        verify(cli, root, dns, origin)


if __name__ == "__main__":
    main(sys.argv[1])
