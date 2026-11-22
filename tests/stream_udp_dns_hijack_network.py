#!/usr/bin/env python3
"""Check ordered DNS hijack on authenticated stream-carried UDP."""
import hashlib
import socket
import ssl
import struct
import sys
import tempfile
import uuid
from pathlib import Path

from dns_rule_support import DnsPeer, exact, free_port, nexus_process, question, wire_name
from udp_bind_port_network import certificate

UUID = uuid.UUID("00010203-0405-0607-0809-0a0b0c0d0e0f")
PASSWORD = "dns-proxy-test"


def frame(data, target):
    size = len(data).to_bytes(2, "big")
    return target + size + (b"\r\n" if target else b"") + data


def verify(cli, root, dns, protocol):
    port = free_port()
    target_port = free_port()
    config = root / "test.kdl"
    auth = (f'password-file="{root / "password"}"' if protocol == "trojan" else
            f'uuid-file="{root / "uuid"}"')
    (root / "target.kdl").write_text(f'schema-version 2\nkind "predicate"\nrule type="port" value="{target_port}"\n')
    config.write_text(f'''schema-version 1
role "server"
inbound "edge" type="{protocol}" {{
    listen host="127.0.0.1" port={port}
    authentication {{ user "test" {auth}; }}
    tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
}}
dns {{
    server "answer" type="udp" host="127.0.0.1" port={dns.port}
    server "other" type="udp" host="127.0.0.1" port=9
    rule domain-suffix="test" network="udp" source-ip-cidr="127.0.0.1/32" inbound="edge" auth-user="test" server="answer"
    final "other"
}}
outbound "direct" type="direct"
routing {{
    rule-set "dns-port" path="target.kdl" format="kdl"
    tcp-program sniff-timeout-ms=200 udp=#true unknown="skip" {{
        rule action="hijack-dns" rule-set="dns-port"
        rule action="route" outbound="direct"
    }}
    default-outbound "direct"
}}
''')
    ip = socket.inet_aton("127.0.0.2")
    target = b"\x01"+ip+target_port.to_bytes(2, "big") if protocol == "trojan" else b""
    if protocol == "trojan":
        initial = hashlib.sha224(PASSWORD.encode()).hexdigest().encode() + b"\r\n\x03\x01" + bytes(6) + b"\r\n"
    else:
        initial = b"\0" + UUID.bytes + struct.pack("!BBHB", 0, 2, target_port, 1) + ip
    tls = ssl.create_default_context(cafile=root / "cert")
    with nexus_process(cli, config), socket.create_connection(("127.0.0.1", port), timeout=4) as transport:
        with tls.wrap_socket(transport, server_hostname="localhost") as client:
            client.sendall(initial + frame(b"bad-message", target))
            if protocol == "vless":
                assert exact(client, 2) == b"\0\0"
            for kind in (1, 28):
                name = f"{protocol}-{kind}.test"
                request = struct.pack("!HHHHHH", 0x3412+kind, 0x100, 1, 0, 0, 0)
                request += wire_name(name) + struct.pack("!HH", kind, 1)
                client.sendall(frame(request, target))
                if target:
                    assert exact(client, len(target)) == target
                size = int.from_bytes(exact(client, 2), "big")
                if target:
                    assert exact(client, 2) == b"\r\n"
                reply = exact(client, size)
                identifier, flags, questions, answers = struct.unpack_from("!4H", reply)
                assert (identifier, flags & 15, questions, answers) == (0x3412+kind, 0, 1, 1)
                assert question(reply)[:2] == (name, kind)
                assert (name, kind, "udp") in dns.seen
    print(f"{protocol} UDP DNS hijack preserved source rules, transaction IDs, A/AAAA and original destination")


def main(cli):
    with tempfile.TemporaryDirectory(prefix="nexus-stream-dns-") as temp, DnsPeer() as dns:
        root = Path(temp)
        certificate(root)
        for name, data in (("uuid", str(UUID)), ("password", PASSWORD)):
            (root / name).write_text(data)
            (root / name).chmod(0o600)
        (root / "key").chmod(0o600)
        for protocol in ("trojan", "vless"):
            verify(cli, root, dns, protocol)


if __name__ == "__main__":
    main(sys.argv[1])
