#!/usr/bin/env python3
"""Independent TLS client for fixed-destination VLESS UDP ingress."""
import contextlib
import socket
import ssl
import struct
import sys
import tempfile
import uuid
from pathlib import Path

from detour_network import exact
from tailscale_endpoint_network import line, process
from udp_bind_port_network import certificate, free_port

IDENTITY = uuid.UUID("00010203-0405-0607-0809-0a0b0c0d0e0f")


def header(identity, family, address, port):
    kind = 1 if family == socket.AF_INET else 3
    return b"\0" + identity.bytes + struct.pack("!BBHB", 0, 2, port, kind) + socket.inet_pton(family, address)


def frame(payload):
    return struct.pack("!H", len(payload)) + payload


@contextlib.contextmanager
def peer(tls, port):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as stream:
        with tls.wrap_socket(stream, server_hostname="localhost") as client:
            yield client


def check(cli, root, ordered):
    program = ('tcp-program sniff-timeout-ms=200 unknown="skip" udp=#true { '
               'rule action="route" outbound="direct"; }; ' if ordered else "")
    port = free_port()
    conf = root / "server.kdl"
    conf.write_text(f'''schema-version 1
role "server"
inbound "edge" type="vless" {{
    listen host="127.0.0.1" port={port}
    authentication {{ user "test" uuid-file="{root / 'uuid'}"; }}
    tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
}}
outbound "direct" type="direct"
routing {{ {program}default-outbound "direct"; }}
''')
    tls = ssl.create_default_context(cafile=root / "cert")
    parked = contextlib.ExitStack()
    with parked, process(["stdbuf", "-oL", cli, "run", "--config", conf]) as server:
        assert b"listening" in line(server).lower()
        for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            with socket.socket(family, socket.SOCK_DGRAM) as origin:
                origin.settimeout(4)
                origin.bind((address, 0))
                target = origin.getsockname()[1]
                request = header(IDENTITY, family, address, target)
                bad = header(uuid.UUID(int=42), family, address, target)
                with peer(tls, port) as denied:
                    denied.sendall(bad + frame(b"bad-auth"))
                    try:
                        closed = denied.recv(1)
                    except (ConnectionResetError, ssl.SSLEOFError):
                        closed = b""
                    assert closed == b"", closed

                client = parked.enter_context(peer(tls, port))
                client.sendall(request[:11])
                client.sendall(request[11:] + frame(b"") + frame(b"coalesced"))
                assert exact(client, 2) == b"\0\0"
                for payload in (b"", b"coalesced"):
                    data, source = origin.recvfrom(65535)
                    assert data == payload, data
                    origin.sendto(data, source)
                    size = struct.unpack("!H", exact(client, 2))[0]
                    assert exact(client, size) == data

                with socket.socket(family, socket.SOCK_DGRAM) as impostor:
                    impostor.sendto(b"spoofed-reply", source)
                client.sendall(b"\0")
                client.sendall(b"\x06fr")
                client.sendall(b"amed")
                data, source = origin.recvfrom(65535)
                assert data == b"framed"
                origin.sendto(data, source)
                assert exact(client, len(frame(data))) == frame(data)
    print(f"VLESS command 2 over TLS passed IPv4/IPv6, framing, empty payload, authorization and active stop (ordered={ordered})")


def main(cli):
    with tempfile.TemporaryDirectory(prefix="nexus-vless-udp-") as tmp:
        root = Path(tmp)
        certificate(root)
        (root / "key").chmod(0o600)
        (root / "uuid").write_text(str(IDENTITY))
        (root / "uuid").chmod(0o600)
        check(cli, root, False)
        check(cli, root, True)


if __name__ == "__main__":
    main(sys.argv[1])
