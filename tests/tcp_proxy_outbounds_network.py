#!/usr/bin/env python3
"""Exercise named SOCKS5 and HTTP/1.1 CONNECT outbounds through the CLI."""
import base64
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from dns_rule_support import DnsPeer, Echo, exact, free_port, nexus_process
from shadowtls_singbox import REVISION, launch_singbox, stop_proc


def open_socks(port, host, destination_port, accepted=True):
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        client.sendall(b"\x05\x01\x00")
        assert exact(client, 2) == b"\x05\x00"
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        request = bytes((5, 1, 0, 4 if family == socket.AF_INET6 else 1))
        client.sendall(request + socket.inet_pton(family, host) + struct.pack("!H", destination_port))
        header = exact(client, 4)
        assert (header[0], header[2]) == (5, 0) and (header[1] == 0) == accepted, header
        assert header[3] in (1, 4), header
        exact(client, 6 if header[3] == 1 else 18)
        return client
    except BaseException:
        client.close()
        raise


def write_config(path, port, outbounds, selected, dns=""):
    path.write_text(f'''schema-version 1
role "client"
inbounds {{
    socks5 "entry" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
}}
outbounds {{
    direct "direct" {{ inet4-bind-address "127.0.0.1"; }}
    {outbounds}
}}
routing {{ default-outbound "{selected}"; }}
{dns}
''')


def authenticated(binary, root):
    version = subprocess.check_output(["sing-box", "version"], text=True)
    assert f"Revision: {REVISION}" in version, version
    password = root / "password"
    password.write_text("secret:tested\n")
    password.chmod(0o600)
    wrong_password = root / "wrong-password"
    wrong_password.write_text("different\n")
    wrong_password.chmod(0o600)
    ports = {"socks5": free_port(), "http-connect": free_port()}
    peer_config = root / "sing-box.json"
    peer_config.write_text(json.dumps({
        "log": {"level": "warn"},
        "inbounds": [
            {"tag": kind, "type": protocol, "listen": "127.0.0.1", "listen_port": ports[kind],
             "users": [{"username": "alice", "password": "secret:tested"}]}
            for kind, protocol in (("socks5", "socks"), ("http-connect", "http"))
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }))
    peer = launch_singbox(peer_config, ports["socks5"])
    try:
        with Echo() as origin, DnsPeer() as dns_peer:
            config = root / "nexus.kdl"
            for kind, other in (("socks5", "http-connect"), ("http-connect", "socks5")):
                for mode in ("physical", "chain", "wrong"):
                    front = free_port()
                    credential = wrong_password if mode == "wrong" else password
                    chain = f'''
  {other} "carrier" {{
     server host="127.0.0.1" port={ports[other]}
     authentication username="alice" password-file="{password}"
     detour "direct"
  }}
''' if mode == "chain" else ""
                    bootstrap = 'bootstrap-resolver "peer-dns";' if mode == "physical" else ""
                    detour = 'detour "carrier";' if mode == "chain" else ""
                    host = "proxy.test" if bootstrap else "127.0.0.1"
                    dns = f'''
dns {{
    server "peer-dns" type="udp" host="{dns_peer.host}" port={dns_peer.port}
    final "peer-dns"
}}
''' if bootstrap else ""
                    write_config(config, front, f'''
  {kind} "remote" {{
     server host="{host}" port={ports[kind]}
     authentication username="alice" password-file="{credential}"
     {bootstrap}
     {detour}
  }}
{chain}
''', "remote", dns)
                    with nexus_process(binary, config):
                        for destination in ("127.0.0.1", "::1"):
                            with open_socks(front, destination, origin.port, accepted=mode != "wrong") as client:
                                if mode != "wrong":
                                    data = f"{kind}/{mode}/{destination}".encode()
                                    client.sendall(data)
                                    assert exact(client, len(data)) == data
            assert dns_peer.count("proxy.test", 1) >= 1, dns_peer.seen
    finally:
        stop_proc(peer)
    print("Fixed sing-box authenticated SOCKS5 and HTTP CONNECT in both chain orders with IPv4 and IPv6 targets")


def framing(binary, root, stall=False):
    expected = b"CONNECT [::1]:4567 HTTP/1.1\r\nHost: [::1]:4567\r\n"
    password = root / "password"
    proof = base64.b64encode(b"alice:secret:tested")
    expected += b"Proxy-Authorization: Basic " + proof + b"\r\n\r\n"
    errors = []
    with socket.socket() as upstream:
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream.settimeout(5)
        front = free_port()
        config = root / "framing.kdl"
        write_config(config, front, f'''
  http-connect "remote" {{
     server host="127.0.0.1" port={upstream.getsockname()[1]}
     authentication username="alice" password-file="{password}"
     connect-timeout-ms {350 if stall else 2500}
  }}
''', "remote")

        def serve():
            try:
                peer, _ = upstream.accept()
                with peer:
                    peer.settimeout(4)
                    assert exact(peer, len(expected)) == expected
                    if not stall:
                        peer.sendall(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Established\r\n"
                                     b"Content-Length: 999\r\n\r\nfirst")
                        assert exact(peer, 6) == b"upload"
                    assert peer.recv(1) == b""
                    if not stall:
                        peer.sendall(b"after-fin")
                        peer.shutdown(socket.SHUT_WR)
            except BaseException as error:
                errors.append(error)

        server = threading.Thread(target=serve)
        server.start()
        try:
            with nexus_process(binary, config):
                started = time.monotonic()
                with open_socks(front, "::1", 4567, accepted=not stall) as client:
                    if stall:
                        assert .18 < time.monotonic() - started < 2
                    else:
                        assert exact(client, 5) == b"first"
                        client.sendall(b"upload")
                        client.shutdown(socket.SHUT_WR)
                        assert exact(client, 9) == b"after-fin"
                        assert client.recv(1) == b""
        finally:
            server.join(6)
        assert not server.is_alive()
        if errors:
            raise errors[0]


def http_inbound(binary, root):
    password = root / "password"
    proof = base64.b64encode(b"alice:secret:tested")
    authentication = b"Proxy-Authorization: Basic " + proof + b"\r\n"
    for family, host, authority_host in ((socket.AF_INET, "127.0.0.1", "127.0.0.1"),
                                          (socket.AF_INET6, "::1", "[::1]")):
        front = free_port()
        config = root / "http-inbound.kdl"
        config.write_text(f'''schema-version 1
role "server"
inbounds {{
    http "entry" {{
        listen host="{host}" port={front}
        authentication "password" username="alice" password-file="{password}"
    }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        with Echo() as origin, nexus_process(binary, config):
            with socket.create_connection((host, front), timeout=3) as client:
                client.sendall(b"\x05\x01\x00")
                try:
                    assert client.recv(2) == b""
                except ConnectionResetError:
                    pass
            authority = f"{authority_host}:{origin.port}".encode()
            connect = b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n"
            with socket.create_connection((host, front), timeout=3) as client:
                client.sendall(connect + b"\r\n")
                assert response_header(client).startswith(b"HTTP/1.1 407 ")
            with socket.create_connection((host, front), timeout=3) as client:
                client.sendall(connect + authentication + b"\r\nhttp-ingress")
                assert response_header(client).startswith(b"HTTP/1.1 200 ")
                assert exact(client, 12) == b"http-ingress"

        with socket.socket(family) as origin:
            origin.settimeout(5)
            origin.bind((host, 0))
            origin.listen(1)
            authority = f"{authority_host}:{origin.getsockname()[1]}".encode()
            with nexus_process(binary, config), socket.create_connection((host, front), timeout=4) as client:
                client.sendall(b"GET http://" + authority + b"/path HTTP/1.1\r\nHost: " + authority + b"\r\n" +
                               authentication + b"Connection: close\r\n\r\n")
                with origin.accept()[0] as target:
                    target.settimeout(3)
                    request = response_header(target)
                    assert request.startswith(b"GET /path HTTP/1.1\r\n")
                    assert b"proxy-authorization:" not in request.lower()
                    target.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody")
                assert response_header(client).startswith(b"HTTP/1.1 200 ")
                assert exact(client, 4) == b"body"
    print("HTTP-only inbound carried authenticated dual-stack CONNECT and HTTP forwarding and rejected SOCKS")


def response_header(peer):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        assert len(data) < 16384
        data.extend(exact(peer, 1))
    return bytes(data)


if __name__ == "__main__":
    cli = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-tcp-upstream-") as folder:
        path = Path(folder)
        authenticated(cli, path)
        framing(cli, path)
        framing(cli, path, stall=True)
        http_inbound(cli, path)
    print("HTTP CONNECT replayed post-header data once, carried a half-close and bounded a stalled handshake")
