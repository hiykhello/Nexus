#!/usr/bin/env python3
"""Route only the supported protocols detected on actual proxy traffic."""
from pathlib import Path
import json
import socket
import ssl
import struct
import subprocess
import sys
import tempfile

from dns_rule_support import connect, exact, free_port, nexus_process, udp_client, wire_name
from ordered_tcp_network import headers


def tls_hello():
    outgoing = ssl.MemoryBIO()
    client = ssl.create_default_context().wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname="example.test")
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        return outgoing.read()
    raise RuntimeError("TLS fixture did not produce a ClientHello")


def check_tcp(front, origin):
    destination = origin.getsockname()[1]
    request = f"CONNECT 127.0.0.1:{destination} HTTP/1.1\r\nHost: 127.0.0.1:{destination}\r\n\r\n".encode()
    for payload, accepted in (
        (b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nbody", True),
        (b"GET / HTTP/1.1\r\nHost: DENIED.example\r\n\r\n", False),
        (b"GET / HTTP/1.1\r\nHost: notdenied.example\r\n\r\n", True),
        (b"SSH-2.0-OpenSSH_10.0\r\n", False),
        (b"SSH-2.0-\r\n", True),
        (tls_hello(), False),
        (b"\x16\x00\x00\x00\x00", True),
    ):
        with connect(front) as client:
            if payload.startswith(b"SSH-"):
                client.sendall(request + payload[:5])
                client.sendall(payload[5:])
            else:
                client.sendall(request + payload)
            reply = headers(client)
            expected = b"HTTP/1.1 200 " if accepted else b"HTTP/1.1 403 "
            if not reply.startswith(expected):
                raise RuntimeError(f"unexpected CONNECT response {reply!r}")
            if accepted:
                target, _ = origin.accept()
                with target:
                    target.settimeout(3)
                    if exact(target, len(payload)) != payload:
                        raise RuntimeError("CONNECT replay changed the first payload")
                    target.sendall(b"OK")
                    if exact(client, 2) != b"OK":
                        raise RuntimeError("CONNECT reply changed")


def check_udp(front, echo):
    address, port = echo.getsockname()
    prefix = b"\x00\x00\x00\x01" + socket.inet_aton(address) + struct.pack("!H", port)
    query = bytes.fromhex("123401000001000000000000") + wire_name("_service.example.test") + struct.pack("!HH", 1, 1)
    stun = struct.pack("!HHI12sHH8s", 1, 12, 0x2112A442, b"0123456789ab", 0x8022, 5, b"Nexus")
    with udp_client(front) as (client, relay):
        for name, rejected in (("dns", query), ("stun", stun)):
            client.sendto(prefix + rejected, relay)
            echo.settimeout(.3)
            try:
                echo.recvfrom(2048)
            except TimeoutError:
                pass
            else:
                raise RuntimeError(f"protocol={name} did not block a valid message")
        echo.settimeout(3)
        for payload in (b"plain UDP", query[:-1], stun[:-1], stun[:22] + b"\x00\xff" + stun[24:]):
            client.sendto(prefix + payload, relay)
            body, source = echo.recvfrom(2048)
            if body != payload:
                raise RuntimeError("UDP forwarding changed the packet")
            echo.sendto(body, source)
            if client.recv(2048) != prefix + payload:
                raise RuntimeError("UDP reply changed")


def main(binary):
    with tempfile.TemporaryDirectory() as folder, socket.socket() as origin, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo:
        root = Path(folder)
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(3)
        echo.bind(("127.0.0.1", 0))
        front = free_port()
        for protocol in ("http", "tls", "dns", "ssh", "stun"):
            source = root / f"{protocol}.kdl"
            predicate = f'rule type="protocol" value="{protocol}"'
            if protocol == "http":
                pattern = json.dumps(r"^(denied|blocked)\.example$")
                predicate = f'rule type="and" {{ {predicate}; rule type="domain-regex" value={pattern}; }}'
            source.write_text(f'schema-version 2\nkind "predicate"\n{predicate}\n')
        subprocess.run([binary, "rule", "convert", "kdl", "beve", root / "tls.kdl", root / "tls.beve"], check=True)
        subprocess.run([binary, "rule", "convert", "beve", "kdl", root / "tls.beve", root / "converted.kdl"], check=True)
        config = root / "config.kdl"
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
routing {{
  rulesets {{
      "http" path="http.kdl" format="kdl"
      "tls" path="tls.beve" format="beve"
      "dns" path="dns.kdl" format="kdl"
      "ssh" path="ssh.kdl" format="kdl"
      "stun" path="stun.kdl" format="kdl"
  }}
  tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{
    rule action="sniff"
    rule action="reject" rule-set="http" domain-source="sniffed"
    rule action="reject" rule-set="tls"
    rule action="reject" rule-set="dns"
    rule action="reject" rule-set="ssh"
    rule action="reject" rule-set="stun"
  }}
  final "direct"
}}
''')
        with nexus_process(binary, config):
            check_tcp(front, origin)
            check_udp(front, echo)
        print("HTTP regex, TLS/SSH and UDP DNS/STUN rejection, malformed fallback and replay passed")


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve(strict=True)))
