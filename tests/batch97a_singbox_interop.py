#!/usr/bin/env python3
"""Batch 97A: Bidirectional sing-box interop torture (SOCKS5 UDP NAT, HTTP CONNECT/Forward, multi-hop detour, sniff replay)."""
import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from contextlib import ExitStack
from pathlib import Path

from detour_network import exact, reserve, running, socks
from dns_rule_support import Echo, nexus_process, udp_client
from tuic_singbox import REVISION, launch_singbox, start_tcp_echo, start_udp_echo, stop_proc


def make_cert(root, cn="allowed.example"):
    cert, key = root / f"{cn}.crt", root / f"{cn}.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", f"/CN={cn}",
        "-addext", f"subjectAltName=DNS:{cn},DNS:blocked.example,DNS:localhost,IP:127.0.0.1", "-days", "1",
    ], check=True, capture_output=True)
    key.chmod(0o600)
    return cert, key


def socks_udp_multi_target(proxy_port, targets):
    with udp_client(proxy_port) as (udp, relay):
        udp.settimeout(5)
        for idx, (host, port) in enumerate(targets):
            payload = f"nat-target-{idx}-".encode() + os.urandom(24)
            pkt = b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port) + payload
            udp.sendto(pkt, relay)
            rx, _ = udp.recvfrom(65535)
            assert rx[4:8] == socket.inet_aton(host), rx[:10]
            assert struct.unpack("!H", rx[8:10])[0] == port, rx[:10]
            assert rx[10:] == payload, "UDP NAT payload mismatch"


def http_connect_echo(proxy_port, dst_host, dst_port, payload):
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as s:
        s.settimeout(5)
        s.sendall(f"CONNECT {dst_host}:{dst_port} HTTP/1.1\r\nHost: {dst_host}:{dst_port}\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            assert chunk, "EOF waiting for CONNECT response"
            buf += chunk
        assert buf.startswith(b"HTTP/1.1 200") or buf.startswith(b"HTTP/1.0 200"), buf
        s.sendall(payload)
        assert exact(s, len(payload)) == payload


def test_bidirectional_socks_udp_nat(binary, root):
    u1, p1, st1 = start_udp_echo()
    u2, p2, st2 = start_udp_echo()
    t1, tp1, tst1 = start_tcp_echo()
    try:
        # Direction A: sing-box Client -> Nexus SOCKS5 Server (TCP + multi-target UDP NAT)
        nx_socks, sb_socks = reserve(), reserve()
        nx_cfg = root / "nx_socks_srv.kdl"
        nx_cfg.write_text(f'''schema-version 1
role "server"
workers 2
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={nx_socks}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
        sb_cfg = root / "sb_socks_cli.json"
        sb_cfg.write_text(json.dumps({
            "log": {"level": "error"},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": sb_socks}],
            "outbounds": [{"type": "socks", "tag": "nx", "server": "127.0.0.1", "server_port": nx_socks}],
            "route": {"final": "nx"},
        }))
        with nexus_process(str(binary), str(nx_cfg)):
            sb = launch_singbox(sb_cfg, sb_socks)
            try:
                with socks(sb_socks, 1, ("127.0.0.1", tp1))[0] as c:
                    blob = os.urandom(32768)
                    c.sendall(blob)
                    assert exact(c, len(blob)) == blob
                socks_udp_multi_target(sb_socks, [("127.0.0.1", p1), ("127.0.0.1", p2), ("127.0.0.1", p1)])
            finally:
                stop_proc(sb)

        # Direction B: Nexus Client -> sing-box SOCKS5 Server (TCP + multi-target UDP NAT)
        sb_srv_p, nx_cli_p = reserve(), reserve()
        sb_srv = root / "sb_socks_srv.json"
        sb_srv.write_text(json.dumps({
            "log": {"level": "error"},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": sb_srv_p}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }))
        nx_cli = root / "nx_socks_cli.kdl"
        nx_cli.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={nx_cli_p}; authentication "none"; }}
outbound "direct" type="direct"
outbound "sb" type="socks5" {{ server host="127.0.0.1" port={sb_srv_p}; udp #true; }}
routing {{ final "sb"; }}
''')
        sb = launch_singbox(sb_srv, sb_srv_p)
        try:
            with nexus_process(str(binary), str(nx_cli)):
                with socks(nx_cli_p, 1, ("127.0.0.1", tp1))[0] as c:
                    blob = os.urandom(32768)
                    c.sendall(blob)
                    assert exact(c, len(blob)) == blob
                socks_udp_multi_target(nx_cli_p, [("127.0.0.1", p1), ("127.0.0.1", p2)])
        finally:
            stop_proc(sb)
        print("97A.1 bidirectional SOCKS5 TCP + multi-target UDP NAT passed")
    finally:
        st1.set(); st2.set(); tst1.set(); u1.close(); u2.close(); t1.close()


def test_bidirectional_http_connect_and_forward(binary, root):
    t1, tp1, tst1 = start_tcp_echo()
    # Mini HTTP origin for forward proxy verification
    http_srv = socket.socket()
    http_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    http_srv.bind(("127.0.0.1", 0))
    http_srv.listen(8)
    http_port = http_srv.getsockname()[1]
    stop = threading.Event()
    def serve_http():
        http_srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = http_srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with c:
                c.settimeout(3)
                req = c.recv(4096)
                body = b"FORWARD-OK-97A"
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\n" + body)
    th = threading.Thread(target=serve_http, daemon=True)
    th.start()
    try:
        # sing-box HTTP outbound -> Nexus HTTP inbound (CONNECT + forward)
        nx_http, sb_http = reserve(), reserve()
        nx_cfg = root / "nx_http_srv.kdl"
        nx_cfg.write_text(f'''schema-version 1
role "server"
workers 2
inbound "http" type="http" {{ listen host="127.0.0.1" port={nx_http}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
        sb_cfg = root / "sb_http_cli.json"
        sb_cfg.write_text(json.dumps({
            "log": {"level": "error"},
            "inbounds": [{"type": "http", "listen": "127.0.0.1", "listen_port": sb_http}],
            "outbounds": [{"type": "http", "tag": "nx", "server": "127.0.0.1", "server_port": nx_http}],
            "route": {"final": "nx"},
        }))
        with nexus_process(str(binary), str(nx_cfg)):
            sb = launch_singbox(sb_cfg, sb_http)
            try:
                http_connect_echo(sb_http, "127.0.0.1", tp1, os.urandom(16384))
                with socket.create_connection(("127.0.0.1", nx_http), timeout=5) as c:
                    c.sendall(f"GET http://127.0.0.1:{http_port}/ok HTTP/1.1\r\nHost: 127.0.0.1:{http_port}\r\nConnection: close\r\n\r\n".encode())
                    resp = b""
                    while chunk := c.recv(4096):
                        resp += chunk
                    assert b"FORWARD-OK-97A" in resp, resp
            finally:
                stop_proc(sb)

        # Nexus HTTP outbound -> sing-box HTTP inbound
        sb_srv_p, nx_cli_p = reserve(), reserve()
        sb_srv = root / "sb_http_srv.json"
        sb_srv.write_text(json.dumps({
            "log": {"level": "error"},
            "inbounds": [{"type": "http", "listen": "127.0.0.1", "listen_port": sb_srv_p}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }))
        nx_cli = root / "nx_http_cli.kdl"
        nx_cli.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="http" {{ listen host="127.0.0.1" port={nx_cli_p}; authentication "none"; }}
outbound "direct" type="direct"
outbound "sb" type="http-connect" {{ server host="127.0.0.1" port={sb_srv_p}; }}
routing {{ final "sb"; }}
''')
        sb = launch_singbox(sb_srv, sb_srv_p)
        try:
            with nexus_process(str(binary), str(nx_cli)):
                http_connect_echo(nx_cli_p, "127.0.0.1", tp1, os.urandom(16384))
        finally:
            stop_proc(sb)
        print("97A.2 bidirectional HTTP CONNECT + Forward passed")
    finally:
        stop.set(); tst1.set(); http_srv.close(); t1.close()


def test_multihop_detour_and_sniff_replay(binary, root):
    cert, key = make_cert(root, "allowed.example")
    psk = base64.b64encode(bytes(range(16))).decode()
    (root / "psk").write_text(psk + "\n"); (root / "psk").chmod(0o600)
    (root / "trojan.pwd").write_text("detour-secret-97a\n"); (root / "trojan.pwd").chmod(0o600)

    # TLS echo origin for SNI sniff replay
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    tls_srv = socket.socket()
    tls_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tls_srv.bind(("127.0.0.1", 0))
    tls_srv.listen(8)
    tls_port = tls_srv.getsockname()[1]
    stop = threading.Event()
    def serve_tls():
        tls_srv.settimeout(0.2)
        while not stop.is_set():
            try:
                raw, _ = tls_srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                with ctx.wrap_socket(raw, server_side=True) as s:
                    s.settimeout(5)
                    while data := s.recv(16384):
                        s.sendall(data)
            except OSError:
                raw.close()
    threading.Thread(target=serve_tls, daemon=True).start()

    try:
        # 3-hop mixed chain: Client -> Nexus1 (SOCKS5+sniff) -> sing-box (SS-2022) -> Nexus2 (Trojan+domain rule) -> TLS Origin
        nx2_trojan, sb_ss, nx1_socks = reserve(), reserve(), reserve()
        nx2_cfg = root / "nx2_exit.kdl"
        nx2_cfg.write_text(f'''schema-version 1
role "server"
workers 2
inbound "trojan" type="trojan" {{
    listen host="127.0.0.1" port={nx2_trojan}
    authentication {{ user "u" password-file="{root / 'trojan.pwd'}"; }}
    tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
}}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{
    tcp-program sniff-timeout-ms=1000 unknown="skip" {{
        rule action="sniff"
        rule action="reject" domain-source="sniffed" {{ domain "blocked.example"; }}
        rule action="route" outbound="direct" domain-source="sniffed" {{ domain "allowed.example"; }}
        rule action="reject"
    }}
    final "direct"
}}
''')
        sb_mid = root / "sb_mid.json"
        sb_mid.write_text(json.dumps({
            "log": {"level": "error"},
            "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": sb_ss,
                          "method": "2022-blake3-aes-128-gcm", "password": psk}],
            "outbounds": [{"type": "trojan", "tag": "exit", "server": "127.0.0.1", "server_port": nx2_trojan,
                           "password": "detour-secret-97a",
                           "tls": {"enabled": True, "server_name": "allowed.example", "certificate_path": str(cert)}}],
            "route": {"final": "exit"},
        }))
        nx1_cfg = root / "nx1_entry.kdl"
        nx1_cfg.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={nx1_socks}; authentication "none"; }}
outbound "direct" type="direct"
outbound "mid" type="shadowsocks" {{
    server host="127.0.0.1" port={sb_ss}
    method "2022-blake3-aes-128-gcm"
    key-file "{root / 'psk'}"
}}
routing {{ final "mid"; }}
''')
        cctx = ssl.create_default_context(cafile=str(cert))
        with nexus_process(str(binary), str(nx2_cfg)):
            sb = launch_singbox(sb_mid, sb_ss)
            try:
                with nexus_process(str(binary), str(nx1_cfg)):
                    # Allowed SNI through 3-hop chain + sniff replay + 128 KiB integrity
                    raw = socks(nx1_socks, 1, ("127.0.0.1", tls_port))[0]
                    with cctx.wrap_socket(raw, server_hostname="allowed.example") as tls_s:
                        tls_s.settimeout(8)
                        blob = os.urandom(131072)
                        tls_s.sendall(blob)
                        assert hashlib.sha256(exact(tls_s, len(blob))).digest() == hashlib.sha256(blob).digest()
                    # Blocked SNI must be rejected by Nexus2 sniff rule!
                    raw2 = socks(nx1_socks, 1, ("127.0.0.1", tls_port))[0]
                    blocked_ok = False
                    try:
                        with cctx.wrap_socket(raw2, server_hostname="blocked.example") as tls_b:
                            tls_b.settimeout(3)
                            tls_b.sendall(b"should-fail")
                            if not tls_b.recv(16):
                                blocked_ok = True
                    except (ssl.SSLError, OSError):
                        blocked_ok = True
                    assert blocked_ok, "blocked.example SNI was not rejected!"
            finally:
                stop_proc(sb)
        print("97A.3 3-hop mixed detour (Nexus->sing-box->Nexus) + TLS SNI sniff replay/block passed")
    finally:
        stop.set(); tls_srv.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("binary", type=Path)
    args = p.parse_args()
    ver = subprocess.check_output(["sing-box", "version"], text=True)
    assert f"Revision: {REVISION}" in ver, ver
    with tempfile.TemporaryDirectory(prefix="nexus-batch97a-") as d:
        root = Path(d)
        test_bidirectional_socks_udp_nat(args.binary.resolve(), root)
        test_bidirectional_http_connect_and_forward(args.binary.resolve(), root)
        test_multihop_detour_and_sniff_replay(args.binary.resolve(), root)
    print("ALL BATCH 97A SING-BOX INTEROP TORTURE TESTS PASSED")


if __name__ == "__main__":
    main()
