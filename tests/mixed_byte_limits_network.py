#!/usr/bin/env python3
"""Mixed TCP, HTTP forwarding and UDP byte quotas through the CLI."""
import base64
from pathlib import Path
import socket
import struct
import sys
import tempfile

from anytls_test_peer import address
from dns_rule_support import Echo, connect, datagram_request, exact, free_port, nexus_process
from principal_limits_network import socks_auth, usage


def config(root, front, quota, ordered):
    path = root / "mixed.kdl"
    program = '''tcp-program unknown="skip" sniff-timeout-ms=500 udp=#true {
  rule action="route" outbound="direct"
 }''' if ordered else ""
    path.write_text(f'''schema-version 1
role "client"
workers 2
control socket="{root / 'control'}"
inbound "local" type="mixed" {{
 listen host="127.0.0.1" port={front}
 authentication "password" username="alice" password-file="{root / 'alice'}"
 user-limits {{ user "alice" byte-quota={quota}; }}
}}
outbound "direct" type="direct" {{ tcp-fast-open #true; }}
routing {{
 {program}
 default-outbound "direct"
}}
''')
    return path


def udp_associate(control, client):
    client.bind(("127.0.0.1", 0))
    control.sendall(b"\x05\x03\x00" + address("127.0.0.1", client.getsockname()[1]))
    reply = exact(control, 10)
    assert reply[:4] == b"\x05\x00\x00\x01"
    return socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:10])[0]


def headers(stream):
    result = bytearray()
    while len(result) < 8192:
        result.extend(exact(stream, 1))
        if result.endswith(b"\r\n\r\n"):
            return bytes(result)
    raise AssertionError("response headers exceeded fixture limit")


def connect_and_udp(binary, root, ordered):
    front = free_port()
    control = root / "control"
    with nexus_process(binary, config(root, front, 45, ordered)), Echo() as origin:
        with connect(front) as client:
            target = f"127.0.0.1:{origin.port}"
            token = base64.b64encode(b"alice:alice").decode()
            client.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {token}\r\n\r\n".encode() + b"alice")
            assert headers(client).startswith(b"HTTP/1.1 200 ")
            assert exact(client, 5) == b"alice"
        with socks_auth(front, 0) as established, socket.socket(type=socket.SOCK_DGRAM) as udp:
            relay = udp_associate(established, udp)
            datagram_request(udp, relay, origin.port, "127.0.0.1")
            usage(binary, control, 0, "alice", upload=22, download=22, unconfirmed=0)
            arrived = len(origin.received)
            datagram_request(udp, relay, origin.port, "127.0.0.1", success=False)
            assert len(origin.received) == arrived
            usage(binary, control, 0, "alice", upload=22, download=22, byte_limit_denials=1)


def forward_http(binary, root, ordered):
    front = free_port()
    control = root / "control"
    with socket.socket() as listener, nexus_process(binary, config(root, front, 1024, ordered)):
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        target = f"127.0.0.1:{listener.getsockname()[1]}"
        token = base64.b64encode(b"alice:alice").decode()
        with connect(front) as client:
            client.sendall(f"POST http://{target}/upload HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {token}\r\nContent-Length: 4\r\n\r\nping".encode())
            with listener.accept()[0] as origin:
                origin.settimeout(5)
                request = headers(origin)
                assert request.startswith(b"POST /upload HTTP/1.1\r\n")
                assert b"proxy-authorization:" not in request.lower()
                assert exact(origin, 4) == b"ping"
                origin.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong")
                origin.shutdown(socket.SHUT_WR)
                reply = headers(client)
                assert reply.startswith(b"HTTP/1.1 200 ")
                assert exact(client, 4) == b"pong"
            usage(binary, control, 0, "alice", upload=len(request) + 4, download=len(reply) + 4, unconfirmed=0)


if __name__ == "__main__":
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-mixed-byte-limits-") as folder:
        root = Path(folder)
        secret = root / "alice"
        secret.write_text("alice\n")
        secret.chmod(0o600)
        for ordered in (False, True):
            connect_and_udp(binary, root, ordered)
            forward_http(binary, root, ordered)
            print(f"Mixed CONNECT pre-read, HTTP forwarding and UDP byte limits passed, ordered={ordered}", flush=True)
