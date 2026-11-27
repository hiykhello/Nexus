#!/usr/bin/env python3
"""Bidirectional ShadowTLS v3 (+ Shadowsocks-2022 + uTLS) interop against sing-box."""
import argparse
import base64
from contextlib import ExitStack
import json
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from udp_bind_port_network import SourceRelay

REVISION = "824dbcfb4dd0a95921840b1737b950cde590241e"


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_tcp_echo():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    stop = threading.Event()

    def handle(conn):
        with conn:
            while not stop.is_set():
                try:
                    data = conn.recv(65535)
                except OSError:
                    break
                if not data:
                    break
                conn.sendall(data)

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
            except TimeoutError:
                pass
            except OSError:
                break

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return srv, srv.getsockname()[1], stop


def start_tls13_cover(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    stop = threading.Event()

    def handle(raw):
        try:
            with ctx.wrap_socket(raw, server_side=True) as tls:
                tls.settimeout(2.0)
                if tls.recv(64):
                    tls.sendall(b"COVER-TLS13-OK")
        except Exception:
            pass
        finally:
            raw.close()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
            except TimeoutError:
                pass
            except OSError:
                break

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return srv, srv.getsockname()[1], stop


def launch_nexus(nexus_bin, cfg_path, ready_prefix, trace=None):
    tracing = [] if trace is None else ["strace", "-D", "-f", "-e", "trace=sendto", "-s", "16", "-o", str(trace)]
    proc = subprocess.Popen(
        ["stdbuf", "-oL", *tracing, nexus_bin, "run", "--config", str(cfg_path)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    deadline = time.monotonic() + 10
    lines = []
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            continue
        lines.append(line.rstrip())
        if line.startswith(ready_prefix):
            port = int(line.rsplit(":", 1)[1].strip())
            return proc, port
    proc.kill()
    out = "\n".join(lines) + proc.stdout.read()
    raise RuntimeError(f"failed starting nexus ({ready_prefix}):\n{out}")


def launch_singbox(cfg_path, check_port):
    subprocess.run(["sing-box", "check", "-c", str(cfg_path)], check=True, capture_output=True, text=True)
    proc = subprocess.Popen(
        ["sing-box", "run", "-c", str(cfg_path)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"sing-box exited early:\n{proc.stdout.read()}")
        try:
            with socket.create_connection(("127.0.0.1", check_port), timeout=0.2):
                return proc
        except OSError:
            time.sleep(0.05)
    proc.kill()
    raise RuntimeError(f"sing-box failed listening on {check_port}:\n{proc.stdout.read()}")


def socks5_tcp_echo(proxy_port, dst_host, dst_port, payload):
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=8) as s:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 greeting rejected")
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(dst_host) + struct.pack("!H", dst_port))
        rep = s.recv(10)
        if len(rep) < 4 or rep[1] != 0:
            raise RuntimeError(f"SOCKS5 CONNECT failed: {rep!r}")
        s.sendall(payload)
        got = bytearray()
        while len(got) < len(payload):
            chunk = s.recv(len(payload) - len(got))
            if not chunk:
                raise RuntimeError("unexpected EOF on TCP echo")
            got.extend(chunk)
        if bytes(got) != payload:
            raise RuntimeError(f"TCP echo mismatch: {bytes(got)!r} != {payload!r}")


def stop_proc(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def run_interop(nexus_bin, user_limits=False, byte_limits=False, fast_open=False):
    ver = subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout
    if f"Revision: {REVISION}" not in ver:
        raise RuntimeError(f"unexpected sing-box revision:\n{ver}")

    tcp_srv, tcp_port, tcp_stop = start_tcp_echo()
    with tempfile.TemporaryDirectory(prefix="nexus-stls-sb-") as tmp, ExitStack() as resources:
        root = Path(tmp)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1",
            ],
            check=True, capture_output=True,
        )
        stls_pass = "stls-interop-secret"
        pass_f = root / "pass.txt"
        pass_f.write_text(stls_pass + "\n")
        os.chmod(pass_f, 0o600)
        ss_b64 = base64.b64encode(bytes(range(16))).decode()
        ss_key_f = root / "ss.key"
        ss_key_f.write_text(ss_b64 + "\n")
        os.chmod(ss_key_f, 0o600)

        cover_srv, cover_port, cover_stop = start_tls13_cover(str(cert), str(key))
        procs = []
        try:
            # 1. Nexus client (SS-2022 over ShadowTLS v3 + uTLS presets) -> sing-box server
            sb_stls_port = free_port()
            sb_ss_port = free_port()
            sb_srv_cfg = root / "sb_srv.json"
            sb_srv_cfg.write_text(json.dumps({
                "log": {"level": "warn"},
                "inbounds": [
                    {
                        "type": "shadowtls", "tag": "stls-in",
                        "listen": "127.0.0.1", "listen_port": sb_stls_port,
                        "version": 3, "strict_mode": True,
                        "users": [{"name": "u1", "password": stls_pass}],
                        "handshake": {"server": "127.0.0.1", "server_port": cover_port},
                        "detour": "ss-in",
                    },
                    {
                        "type": "shadowsocks", "tag": "ss-in",
                        "listen": "127.0.0.1", "listen_port": sb_ss_port,
                        "method": "2022-blake3-aes-128-gcm", "password": ss_b64,
                    },
                ],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"final": "direct"},
            }))
            sb_srv = launch_singbox(sb_srv_cfg, sb_stls_port)
            procs.append(sb_srv)
            stls_relay = resources.enter_context(SourceRelay(sb_stls_port))

            for fp in ("chrome", "firefox", "safari"):
                nx_socks_port = free_port()
                nx_cli_cfg = root / f"nx_cli_{fp}.kdl"
                use_direct = fp == "safari"
                detour = 'detour "direct";' if use_direct else ""
                fast = fast_open and fp != "firefox"
                inherited = 'tcp-fast-open #true;' if fast and use_direct else ""
                own = f'tcp-fast-open #{str(fast).lower()};' if fast_open and not use_direct else ""
                trace = root / f"trace-{fp}" if fast_open else None
                nx_cli_cfg.write_text(f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={nx_socks_port}; authentication "none"; }}
outbound "direct" type="direct" {{ inet4-bind-address "127.0.0.2"; {inherited} }}
outbound "stls" type="shadowtls" {{
    server host="127.0.0.1" port={stls_relay.port}
    {detour}
    {own}
    strict-tls13 #true
    authentication {{ password-file "{pass_f}"; }}
    tls {{ server-name "localhost"; ca-file "{cert}"; fingerprint "{fp}"; verify #true; }}
}}
outbound "ss" type="shadowsocks" {{
    server host="127.0.0.1" port={sb_stls_port}
    method "2022-blake3-aes-128-gcm"
    key-file "{ss_key_f}"
    detour "stls"
}}
routing {{ final "ss"; }}
''')
                start = len(stls_relay.sources)
                c_proc, c_port = launch_nexus(nexus_bin, nx_cli_cfg, "SOCKS5 listening on ", trace)
                try:
                    socks5_tcp_echo(c_port, "127.0.0.1", tcp_port, f"nx-to-sb-{fp}".encode() * 32)
                    expected = "127.0.0.2" if use_direct else "127.0.0.1"
                    assert [host for host, _ in stls_relay.sources[start:]] == [expected], stls_relay.sources
                finally:
                    stop_proc(c_proc)
                if trace is not None:
                    submissions = [line for line in trace.read_text().splitlines() if "MSG_FASTOPEN" in line]
                    if fast:
                        assert len(submissions) == 1, (fp, submissions)
                        assert "\\26\\3" in submissions[0] and f"sin_port=htons({stls_relay.port})" in submissions[0], submissions
                    else:
                        assert not submissions, submissions
            if fast_open:
                print("ShadowTLS sent its authenticated ClientHello with MSG_FASTOPEN for owned and inherited physical options")
            print("Interop Nexus Client (SS-2022 + ShadowTLS v3 uTLS chrome/firefox/safari) -> sing-box Server passed")

            # 2. sing-box client -> Nexus server (ShadowTLS v3 inbound -> Nexus SS-2022 inbound)
            nx_stls_port = free_port()
            nx_ss_port = free_port()
            nx_srv_cfg = root / "nx_srv.kdl"
            control = root / "control"
            control_node = f'control socket="{control}"' if user_limits or byte_limits else ""
            limits_node = 'user-limits { user "u1" connections=1; }' if user_limits else ""
            if byte_limits:
                limits_node = 'user-limits { user "u1" byte-quota=8; }'
            nx_srv_cfg.write_text(f'''schema-version 1
role "server"
{control_node}
inbound "stls-in" type="shadowtls" {{
    listen host="127.0.0.1" port={nx_stls_port}
    handshake host="127.0.0.1" port={cover_port}
    target host="127.0.0.1" port={nx_ss_port}
    strict-tls13 #true
    authentication {{ user "u1" password-file="{pass_f}"; }}
    {limits_node}
}}
inbound "ss-in" type="shadowsocks" {{
    listen host="127.0.0.1" port={nx_ss_port}
    method "2022-blake3-aes-128-gcm"
    key-file "{ss_key_f}"
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
            nx_srv, actual_stls_port = launch_nexus(nexus_bin, nx_srv_cfg, "ShadowTLS listening on ")
            procs.append(nx_srv)

            sb_socks_port = free_port()
            sb_cli_cfg = root / "sb_cli.json"
            sb_cli_cfg.write_text(json.dumps({
                "log": {"level": "warn"},
                "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": sb_socks_port}],
                "outbounds": [
                    {
                        "type": "shadowtls", "tag": "st-out",
                        "server": "127.0.0.1", "server_port": actual_stls_port,
                        "version": 3, "password": stls_pass,
                        "tls": {"enabled": True, "server_name": "localhost", "certificate_path": str(cert)},
                    },
                    {
                        "type": "shadowsocks", "tag": "ss-out",
                        "method": "2022-blake3-aes-128-gcm", "password": ss_b64,
                        "detour": "st-out",
                    },
                ],
                "route": {"final": "ss-out"},
            }))
            sb_cli = launch_singbox(sb_cli_cfg, sb_socks_port)
            procs.append(sb_cli)
            if user_limits:
                from detour_network import exact, socks
                from dns_rule_support import Echo
                from principal_limits_network import usage

                with Echo() as guarded, socks(sb_socks_port, 1, ("127.0.0.1", tcp_port))[0] as active:
                    active.sendall(b"held")
                    assert exact(active, 4) == b"held"
                    usage(nexus_bin, control, 0, "u1", connections=1)
                    with socket.create_connection(("127.0.0.1", sb_socks_port), timeout=5) as refused:
                        refused.sendall(b"\x05\x01\x00")
                        assert exact(refused, 2) == b"\x05\x00"
                        refused.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", guarded.port))
                        assert exact(refused, 2) == b"\x05\x01"
                        assert not guarded.accepted
                    usage(nexus_bin, control, 0, "u1", connections=1, rejected_connections=1)
                    active.sendall(b"live")
                    assert exact(active, 4) == b"live"
                usage(nexus_bin, control, 0, "u1", connections=0)
                print("ShadowTLS authenticated connection quota, old flow and release passed", flush=True)
            if byte_limits:
                from detour_network import exact
                from principal_limits_network import usage

                with socket.create_connection(("127.0.0.1", sb_socks_port), timeout=5) as client:
                    client.sendall(b"\x05\x01\x00")
                    assert exact(client, 2) == b"\x05\x00"
                    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", tcp_port))
                    response = exact(client, 10)
                    assert response[:2] == b"\x05\x00"
                    client.sendall(b"must not reach the origin")
                    assert client.recv(1) == b""
                usage(nexus_bin, control, 0, "u1", upload=8, download=0, byte_limit_denials=1)
                print("ShadowTLS charged its initial authenticated payload", flush=True)
            else:
                socks5_tcp_echo(sb_socks_port, "127.0.0.1", tcp_port, b"sb-to-nx-shadowtls-v3" * 32)

            tls_ctx = ssl.create_default_context(cafile=str(cert))
            with socket.create_connection(("127.0.0.1", actual_stls_port), timeout=5) as raw_sock:
                with tls_ctx.wrap_socket(raw_sock, server_hostname="localhost") as tls_conn:
                    tls_conn.sendall(b"COVER-PING")
                    if tls_conn.recv(64) != b"COVER-TLS13-OK":
                        raise RuntimeError("ShadowTLS cover fallback failed")
            print("Interop sing-box Client (SS-2022 + ShadowTLS v3) -> Nexus Server + cover fallback passed")
        finally:
            for p in reversed(procs):
                stop_proc(p)
            cover_stop.set()
            cover_srv.close()
            tcp_stop.set()
            tcp_srv.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("nexus_bin")
    parser.add_argument("--fast-open", action="store_true")
    limits = parser.add_mutually_exclusive_group()
    limits.add_argument("--user-limits", action="store_true")
    limits.add_argument("--byte-limits", action="store_true")
    args = parser.parse_args()
    run_interop(args.nexus_bin, args.user_limits, args.byte_limits, args.fast_open)
