#!/usr/bin/env python3
"""Verify authenticated TLS to a named HTTP CONNECT proxy."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import socket
import ssl
import sys
import tempfile
import time

from dns_rule_support import exact, free_port, nexus_process
from httpupgrade_tls_network import certificates, header, server_context
from shadowtls_singbox import launch_singbox, stop_proc
from tcp_proxy_outbounds_network import open_socks, write_config


def check(binary, root, mode, carrier_port):
    context = server_context(root, ["http/1.1"])
    password = root / "password"
    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(4)
        port = listener.getsockname()[1]
        front = free_port()
        config = root / "nexus.kdl"
        carrier = f'''
            socks5 "carrier" {{
                server host="127.0.0.1" port={carrier_port}
            }}
        ''' if mode == "layered" else ""
        lower = {
            "layered": 'detour "carrier"',
            "direct": 'detour "direct"',
        }.get(mode, "")
        identity = "invalid.example" if mode == "wrong-name" else "localhost"
        timeout = 400 if mode == "stall" else 2500
        write_config(config, front, f'''
  http-connect "remote" {{
    server host="127.0.0.1" port={port}
    authentication username="alice" password-file="{password}"
    tls {{ server-name "{identity}"; ca-file "{root / 'cert'}"; verify #true; }}
    connect-timeout-ms {timeout}
    {lower}
  }}
  {carrier}
''', "remote")

        if mode == "direct":
            config.write_text(config.read_text().replace('inet4-bind-address "127.0.0.1";',
                                                         'inet4-bind-address "127.0.0.1"; tcp-fast-open #true;'))

        def serve():
            tcp, _ = listener.accept()
            with tcp:
                tcp.settimeout(3)
                if mode == "stall":
                    assert tcp.recv(1) == b"\x16"
                    time.sleep(.6)
                    return
                try:
                    peer = context.wrap_socket(tcp, server_side=True)
                except ssl.SSLError:
                    if mode == "wrong-name":
                        return
                    raise
                with peer:
                    if mode == "wrong-name":
                        try:
                            assert peer.recv(1024) == b""
                        except (ssl.SSLError, ConnectionResetError):
                            pass
                        return
                    assert peer.selected_alpn_protocol() == "http/1.1"
                    request = header(peer)
                    assert request.startswith(b"CONNECT [::1]:4567 HTTP/1.1\r\n"), request
                    assert b"\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n" in request, request
                    peer.sendall(b"HTTP/1.1 200 Connection established\r\n\r\nprefetch")
                    assert exact(peer, 6) == b"upload"
                    peer.sendall(b"reply")

        with ThreadPoolExecutor(max_workers=1) as executor:
            server = executor.submit(serve)
            with nexus_process(binary, config):
                started = time.monotonic()
                accepted = mode not in ("wrong-name", "stall")
                with open_socks(front, "::1", 4567, accepted=accepted) as client:
                    if mode == "stall":
                        assert .28 <= time.monotonic() - started < 1.8
                    if accepted:
                        assert exact(client, 8) == b"prefetch"
                        client.sendall(b"upload")
                        assert exact(client, 5) == b"reply"
            server.result(timeout=4)


if __name__ == "__main__":
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-http-connect-tls-") as directory:
        root = Path(directory)
        certificates(root)
        secret = root / "password"
        secret.write_text("secret\n")
        secret.chmod(0o600)
        port = free_port()
        config = root / "sing-box.json"
        config.write_text(json.dumps({
            "log": {"level": "warn"},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [{"type": "direct"}],
        }))
        peer = launch_singbox(config, port)
        try:
            for mode in ("physical", "direct", "layered", "wrong-name", "stall"):
                check(binary, root, mode, port)
                print(f"HTTP CONNECT TLS {mode} passed")
        finally:
            stop_proc(peer)
