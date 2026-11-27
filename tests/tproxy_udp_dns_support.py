"""DNS interception assertions for the isolated UDP TPROXY fixture."""
from pathlib import Path
import socket
import sys
import tempfile

from dns_rule_support import DnsPeer, nexus_process


def verify_dns_hijack(binary, client_ns, family, listener_address, target_address, firewall, command, ns):
    with tempfile.TemporaryDirectory(prefix="nexus-tproxy-dns-") as directory, DnsPeer() as origin:
        root = Path(directory)
        with socket.socket(family) as spare:
            spare.bind((listener_address, 0))
            port = spare.getsockname()[1]
        config = root / "config.kdl"
        (root / "target.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="port" value="53"\n')
        config.write_text(f'''schema-version 1
role "client"
inbounds {{ tproxy "local" {{ udp #true; listen host="{listener_address}" port={port}; }}; }}
outbound "direct" type="direct"
dns {{
    server "upstream" type="udp" host="127.0.0.1" port={origin.port}
    rule inbound="local" source-interface="nxclienthost" domain="accepted.test" action="route" server="upstream"
    rule action="reject"
    final "upstream"
}}
routing {{
    rulesets {{ "target" path="target.kdl" format="kdl"; }}
    tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{
        rule action="hijack-dns" rule-set="target"
        rule action="reject"
    }}
    final "direct"
}}
''')
        rule = ("-i", "nxclienthost", "-p", "udp", "-d", target_address, "--dport", "53", "-j", "TPROXY",
                "--on-ip", listener_address, "--on-port", str(port), "--tproxy-mark", "42")
        command(firewall, "-t", "mangle", "-A", "PREROUTING", *rule)
        try:
            with nexus_process(binary, config):
                source = r'''
import socket
import struct
import sys

family, target, kind = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
with socket.socket(family, socket.SOCK_DGRAM) as peer:
    peer.settimeout(3)
    for ident, label, rcode, count in ((20001, b"accepted", 0, 1), (20002, b"denied", 5, 0)):
        question = bytes([len(label)]) + label + b"\x04test\x00" + struct.pack("!HH", kind, 1)
        query = struct.pack("!6H", ident, 256, 1, 0, 0, 0) + question
        peer.sendto(query, (target, 53))
        reply, remote = peer.recvfrom(4096)
        assert remote[:2] == (target, 53), remote
        identifier, flags, questions, answers = struct.unpack_from("!4H", reply)
        assert (identifier, flags & 15, questions, answers) == (ident, rcode, 1, count), reply.hex()
        assert reply[12:12 + len(question)] == question, reply.hex()
'''
                ns(client_ns, sys.executable, "-c", source, str(int(family)), target_address,
                   "1" if family == socket.AF_INET else "28")
                assert origin.seen == [("accepted.test", 1 if family == socket.AF_INET else 28, "udp")], origin.seen
        finally:
            command(firewall, "-t", "mangle", "-D", "PREROUTING", *rule)
        print(f"{family.name} UDP TPROXY DNS used the real inbound and interface and replied from the original target")
