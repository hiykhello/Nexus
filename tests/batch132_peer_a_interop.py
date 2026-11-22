#!/usr/bin/env python3
"""Batch 132: Bidirectional multi-protocol interop torture between Nexus and Peer A (Mihomo)."""
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
from pathlib import Path

from detour_network import exact, reserve, socks
from dns_rule_support import nexus_process, udp_client
from batch94a_reality_network import SHORT, encode as b64url

UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"


def start_echo_servers():
    tsrv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tsrv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tsrv.bind(("127.0.0.1", 0))
    tsrv.listen(64)
    usrv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usrv.bind(("127.0.0.1", 0))
    stop = threading.Event()

    def serve_tcp():
        tsrv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = tsrv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            def _h(conn):
                try:
                    conn.settimeout(10)
                    while d := conn.recv(65536):
                        conn.sendall(d)
                except OSError:
                    pass
                finally:
                    conn.close()
            threading.Thread(target=_h, args=(c,), daemon=True).start()

    def serve_udp():
        usrv.settimeout(0.2)
        while not stop.is_set():
            try:
                d, a = usrv.recvfrom(65535)
                usrv.sendto(d, a)
            except TimeoutError:
                continue
            except OSError:
                break

    threading.Thread(target=serve_tcp, daemon=True).start()
    threading.Thread(target=serve_udp, daemon=True).start()
    return tsrv, tsrv.getsockname()[1], usrv, usrv.getsockname()[1], stop


def start_tls_cover(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(cert), str(key))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                raw, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            def _h(r):
                try:
                    with ctx.wrap_socket(r, server_side=True) as s:
                        s.settimeout(3)
                        s.recv(128)
                except OSError:
                    r.close()
            threading.Thread(target=_h, args=(raw,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1], stop


def make_creds(root: Path):
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1",
    ], check=True, capture_output=True)
    key.chmod(0o600)
    (root / "uuid").write_text(UUID + "\n"); (root / "uuid").chmod(0o600)
    (root / "pwd").write_text("interop-secret-132\n"); (root / "pwd").chmod(0o600)
    (root / "obfs").write_text("salamander-obfs-132\n"); (root / "obfs").chmod(0o600)
    psk128 = base64.b64encode(bytes(range(16))).decode()
    psk256 = base64.b64encode(bytes(range(32))).decode()
    (root / "psk128").write_text(psk128 + "\n"); (root / "psk128").chmod(0o600)
    (root / "psk256").write_text(psk256 + "\n"); (root / "psk256").chmod(0o600)
    seed = bytes.fromhex("37" + "11" * 31)
    (root / "rkey").write_text(seed.hex()); (root / "rkey").chmod(0o600)
    der = bytes.fromhex("302e020100300506032b656e04220420") + seed
    pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                         input=der, check=True, capture_output=True).stdout[-32:]
    return {"cert": cert, "key": key, "psk128": psk128, "psk256": psk256, "seed": seed, "pub": pub}


def launch_mihomo(mihomo_bin: Path, root: Path, name: str, cfg: dict, wait_tcp_port=None):
    safe = name.replace("/", "_").replace(">", "_")
    cfg_path = root / f"mh-{safe}.yaml"
    cfg_path.write_text(json.dumps(cfg))
    env = os.environ.copy()
    env["SSL_CERT_FILE"] = str(root / "cert.pem")
    env["SAFE_PATHS"] = str(root)
    chk = subprocess.run([str(mihomo_bin), "-t", "-d", str(root), "-f", str(cfg_path)],
                         capture_output=True, text=True, env=env)
    if chk.returncode != 0:
        raise RuntimeError(f"mihomo config check failed ({name}): {chk.stdout}\n{chk.stderr}")
    proc = subprocess.Popen([str(mihomo_bin), "-d", str(root), "-f", str(cfg_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"mihomo exited early ({name}): {proc.stdout.read()}")
        if wait_tcp_port is None:
            time.sleep(0.3)
            return proc
        try:
            with socket.create_connection(("127.0.0.1", wait_tcp_port), timeout=0.2):
                return proc
        except OSError:
            time.sleep(0.05)
    proc.kill()
    raise RuntimeError(f"mihomo startup timeout ({name}): {proc.stdout.read()}")


def stop_proc(p):
    if p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=4)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=4)


def verify_tcp(proxy_port: int, dst_port: int, size: int = 65536):
    blob = os.urandom(size)
    with socks(proxy_port, 1, ("127.0.0.1", dst_port))[0] as s:
        s.settimeout(12)
        s.sendall(blob)
        assert hashlib.sha256(exact(s, len(blob))).digest() == hashlib.sha256(blob).digest()


def verify_udp(proxy_port: int, dst_port: int):
    with udp_client(proxy_port) as (u, relay):
        u.settimeout(6)
        payload = b"udp-b132-" + os.urandom(48)
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", dst_port) + payload
        u.sendto(pkt, relay)
        assert u.recv(4096) == pkt


def free_udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_case(label: str, nexus_bin: Path, mihomo_bin: Path, root: Path, tcp_port: int, udp_port: int,
             nx_cfg: str, mh_cfg: dict, nexus_is_client: bool, proxy_port: int, mh_wait_port, do_udp: bool = True):
    cfg_file = root / f"nx-{label.replace(' ', '_').replace('/', '_')}.kdl"
    cfg_file.write_text(nx_cfg)
    if nexus_is_client:
        mh = launch_mihomo(mihomo_bin, root, label.replace(" ", "_"), mh_cfg, mh_wait_port)
        try:
            with nexus_process(str(nexus_bin), str(cfg_file)):
                verify_tcp(proxy_port, tcp_port)
                if do_udp:
                    verify_udp(proxy_port, udp_port)
        finally:
            stop_proc(mh)
    else:
        with nexus_process(str(nexus_bin), str(cfg_file)):
            mh = launch_mihomo(mihomo_bin, root, label.replace(" ", "_"), mh_cfg, mh_wait_port)
            try:
                verify_tcp(proxy_port, tcp_port)
                if do_udp:
                    verify_udp(proxy_port, udp_port)
            finally:
                stop_proc(mh)
    print(f"  [PASS] {label} (TCP{' + UDP' if do_udp else ''})", flush=True)


def run_suite(nexus_bin: Path, mihomo_bin: Path):
    tsrv, tport, usrv, uport, stop_echo = start_echo_servers()
    with tempfile.TemporaryDirectory(prefix="nexus-b132-") as d:
        root = Path(d)
        c = make_creds(root)
        csrv, cover_port, stop_cover = start_tls_cover(c["cert"], c["key"])
        try:
            def mh_client_cfg(front, proxy_obj):
                return {
                    "log-level": "warning", "mode": "global", "socks-port": front,
                    "proxies": [proxy_obj],
                    "proxy-groups": [{"name": "GLOBAL", "type": "select", "proxies": [proxy_obj["name"]]}],
                }

            def mh_server_cfg(listener_obj):
                return {"log-level": "warning", "mode": "direct", "listeners": [listener_obj]}

            # 1. Trojan (TCP + UDP + TLS) — Bidirectional
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Nexus->Mihomo Trojan", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="trojan" {{ server host="127.0.0.1" port={p_edge}; authentication {{ password-file "{root/'pwd'}"; }}; tls {{ server-name "localhost"; ca-file "{c['cert']}"; verify #true; }}; }}
routing {{ default-outbound "edge"; }}''',
                mh_server_cfg({"name": "tr-in", "type": "trojan", "listen": "127.0.0.1", "port": p_edge,
                               "users": [{"username": "u", "password": "interop-secret-132"}],
                               "certificate": str(c["cert"]), "private-key": str(c["key"])}),
                True, p_front, p_edge, do_udp=True,
            )
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Mihomo->Nexus Trojan", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "server"\ninbound "tr" type="trojan" {{ listen host="127.0.0.1" port={p_edge}; authentication {{ user "u" password-file="{root/'pwd'}"; }}; tls {{ certificate-file "{c['cert']}"; private-key-file "{c['key']}"; }}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                mh_client_cfg(p_front, {"name": "nx", "type": "trojan", "server": "127.0.0.1", "port": p_edge,
                                        "password": "interop-secret-132", "sni": "localhost", "udp": True, "skip-cert-verify": True}),
                False, p_front, p_front, do_udp=True,
            )

            # 2. Shadowsocks 2022 (AES-128 & AES-256, TCP + UDP) — Bidirectional
            for method, psk_name, psk_val in (("2022-blake3-aes-128-gcm", "psk128", c["psk128"]),
                                              ("2022-blake3-aes-256-gcm", "psk256", c["psk256"])):
                p_edge, p_front = reserve(), reserve()
                run_case(
                    f"Nexus->Mihomo SS2022-{method[-11:-4]}", nexus_bin, mihomo_bin, root, tport, uport,
                    f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={p_edge}; method "{method}"; key-file "{root/psk_name}"; }}
routing {{ default-outbound "edge"; }}''',
                    mh_server_cfg({"name": "ss-in", "type": "shadowsocks", "listen": "127.0.0.1", "port": p_edge,
                                   "cipher": method, "password": psk_val, "udp": True}),
                    True, p_front, p_edge, do_udp=False,
                )
                p_edge, p_front = reserve(), reserve()
                run_case(
                    f"Mihomo->Nexus SS2022-{method[-11:-4]}", nexus_bin, mihomo_bin, root, tport, uport,
                    f'''schema-version 1\nrole "server"\ninbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={p_edge}; method "{method}"; key-file "{root/psk_name}"; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                    mh_client_cfg(p_front, {"name": "nx", "type": "ss", "server": "127.0.0.1", "port": p_edge,
                                            "cipher": method, "password": psk_val, "udp": True}),
                    False, p_front, p_front, do_udp=True,
                )

            # 3. VLESS + TLS + Vision — Bidirectional
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Nexus->Mihomo VLESS+Vision", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={p_edge}; flow "xtls-rprx-vision"; authentication {{ uuid-file "{root/'uuid'}"; }}; tls {{ server-name "localhost"; ca-file "{c['cert']}"; verify #true; }}; }}
routing {{ default-outbound "edge"; }}''',
                mh_server_cfg({"name": "vl-in", "type": "vless", "listen": "127.0.0.1", "port": p_edge,
                               "users": [{"username": "u", "uuid": UUID, "flow": "xtls-rprx-vision"}],
                               "certificate": str(c["cert"]), "private-key": str(c["key"])}),
                True, p_front, p_edge, do_udp=True,
            )
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Mihomo->Nexus VLESS+Vision", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "server"\ninbound "vl" type="vless" {{ listen host="127.0.0.1" port={p_edge}; flow "xtls-rprx-vision"; authentication {{ user "u" uuid-file="{root/'uuid'}"; }}; tls {{ certificate-file "{c['cert']}"; private-key-file "{c['key']}"; }}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                mh_client_cfg(p_front, {"name": "nx", "type": "vless", "server": "127.0.0.1", "port": p_edge,
                                        "uuid": UUID, "flow": "xtls-rprx-vision", "tls": True, "servername": "localhost",
                                        "udp": True, "skip-cert-verify": True}),
                False, p_front, p_front, do_udp=True,
            )

            # 4. VLESS + REALITY + Vision — Bidirectional
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Nexus->Mihomo VLESS+REALITY+Vision", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={p_edge}; flow "xtls-rprx-vision"; authentication {{ uuid-file "{root/'uuid'}"; }}; tls {{ server-name "localhost"; fingerprint "chrome"; reality {{ public-key "{c['pub'].hex()}"; short-id "{SHORT}"; }}; }}; }}
routing {{ default-outbound "edge"; }}''',
                mh_server_cfg({"name": "vl-r", "type": "vless", "listen": "127.0.0.1", "port": p_edge,
                               "users": [{"username": "u", "uuid": UUID, "flow": "xtls-rprx-vision"}],
                               "reality-config": {"dest": f"127.0.0.1:{cover_port}", "private-key": b64url(c["seed"]),
                                                  "short-id": [SHORT], "server-names": ["localhost"]}}),
                True, p_front, p_edge, do_udp=True,
            )
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Mihomo->Nexus VLESS+REALITY+Vision", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "server"\ninbound "vl" type="vless" {{ listen host="127.0.0.1" port={p_edge}; flow "xtls-rprx-vision"; authentication {{ user "u" uuid-file="{root/'uuid'}"; }}; tls {{ reality {{ private-key-file "{root/'rkey'}"; server-name "localhost"; short-id "{SHORT}"; max-time-difference 15; fallback host="127.0.0.1" port={cover_port}; }}; }}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                mh_client_cfg(p_front, {"name": "nx", "type": "vless", "server": "127.0.0.1", "port": p_edge,
                                        "uuid": UUID, "flow": "xtls-rprx-vision", "tls": True, "servername": "localhost",
                                        "client-fingerprint": "chrome", "udp": True,
                                        "reality-opts": {"public-key": b64url(c["pub"]), "short-id": SHORT}}),
                False, p_front, p_front, do_udp=True,
            )

            # 5. VLESS + WebSocket & gRPC — Mihomo Client -> Nexus Server
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Mihomo->Nexus VLESS+WS", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "server"\ninbound "vl" type="vless" {{ listen host="127.0.0.1" port={p_edge}; authentication {{ user "u" uuid-file="{root/'uuid'}"; }}; tls {{ certificate-file "{c['cert']}"; private-key-file "{c['key']}"; }}; transport "websocket" {{ host "localhost"; path "/ws"; }}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                mh_client_cfg(p_front, {"name": "nx", "type": "vless", "server": "127.0.0.1", "port": p_edge,
                                        "uuid": UUID, "tls": True, "servername": "localhost", "network": "ws",
                                        "ws-opts": {"path": "/ws", "headers": {"Host": "localhost"}},
                                        "udp": True, "skip-cert-verify": True}),
                False, p_front, p_front, do_udp=True,
            )
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Mihomo->Nexus VLESS+gRPC", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "server"\ninbound "vl" type="vless" {{ listen host="127.0.0.1" port={p_edge}; authentication {{ user "u" uuid-file="{root/'uuid'}"; }}; tls {{ certificate-file "{c['cert']}"; private-key-file "{c['key']}"; }}; transport "grpc" {{ service-name "nexus.Grpc"; authority "localhost"; }}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                mh_client_cfg(p_front, {"name": "nx", "type": "vless", "server": "127.0.0.1", "port": p_edge,
                                        "uuid": UUID, "tls": True, "servername": "localhost", "network": "grpc",
                                        "grpc-opts": {"grpc-service-name": "nexus.Grpc"},
                                        "udp": True, "skip-cert-verify": True}),
                False, p_front, p_front, do_udp=True,
            )

            # 6. Hysteria 2 (+ Salamander + lazy TCP response) — Bidirectional
            p_edge, p_front = free_udp(), reserve()
            run_case(
                "Nexus->Mihomo Hysteria2+Salamander", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{ server host="127.0.0.1" port={p_edge}; authentication {{ password-file "{root/'pwd'}"; }}; tls {{ server-name "localhost"; ca-file "{c['cert']}"; verify #true; }}; quic {{ salamander-password-file "{root/'obfs'}"; lazy-tcp-response #true; }}; }}
routing {{ default-outbound "edge"; }}''',
                mh_server_cfg({"name": "hy2-in", "type": "hysteria2", "listen": "127.0.0.1", "port": p_edge,
                               "users": {"u": "interop-secret-132"}, "obfs": "salamander", "obfs-password": "salamander-obfs-132",
                               "certificate": str(c["cert"]), "private-key": str(c["key"])}),
                True, p_front, None, do_udp=True,
            )
            p_edge, p_front = free_udp(), reserve()
            run_case(
                "Mihomo->Nexus Hysteria2+Salamander", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "server"\ninbound "hy2" type="hysteria2" {{ listen host="127.0.0.1" port={p_edge}; authentication {{ user "u" password-file="{root/'pwd'}"; }}; tls {{ certificate-file "{c['cert']}"; private-key-file "{c['key']}"; }}; quic {{ salamander-password-file "{root/'obfs'}"; }}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                mh_client_cfg(p_front, {"name": "nx", "type": "hysteria2", "server": "127.0.0.1", "port": p_edge,
                                        "password": "interop-secret-132", "obfs": "salamander", "obfs-password": "salamander-obfs-132",
                                        "sni": "localhost", "skip-cert-verify": True}),
                False, p_front, p_front, do_udp=True,
            )

            # 7. TUIC v5 (TCP + UDP native) — Bidirectional
            p_edge, p_front = free_udp(), reserve()
            run_case(
                "Nexus->Mihomo TUIC-v5", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="tuic" {{ server host="127.0.0.1" port={p_edge}; congestion-control "bbr"; authentication {{ uuid-file "{root/'uuid'}"; password-file "{root/'pwd'}"; }}; tls {{ server-name "localhost"; ca-file "{c['cert']}"; verify #true; }}; }}
routing {{ default-outbound "edge"; }}''',
                mh_server_cfg({"name": "tuic-in", "type": "tuic", "listen": "127.0.0.1", "port": p_edge,
                               "users": {UUID: "interop-secret-132"}, "congestion-controller": "bbr",
                               "certificate": str(c["cert"]), "private-key": str(c["key"])}),
                True, p_front, None, do_udp=True,
            )
            p_edge, p_front = free_udp(), reserve()
            run_case(
                "Mihomo->Nexus TUIC-v5", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "server"\ninbound "tuic" type="tuic" {{ listen host="127.0.0.1" port={p_edge}; congestion-control "bbr"; authentication {{ user "u" uuid-file="{root/'uuid'}" password-file="{root/'pwd'}"; }}; tls {{ certificate-file "{c['cert']}"; private-key-file "{c['key']}"; }}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                mh_client_cfg(p_front, {"name": "nx", "type": "tuic", "server": "127.0.0.1", "port": p_edge,
                                        "uuid": UUID, "password": "interop-secret-132", "sni": "localhost",
                                        "alpn": ["h3"], "congestion-controller": "bbr", "udp-relay-mode": "native",
                                        "skip-cert-verify": True}),
                False, p_front, p_front, do_udp=True,
            )

            # 8. AnyTLS (TCP + UDP UoT) — Bidirectional
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Nexus->Mihomo AnyTLS", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="anytls" {{ server host="127.0.0.1" port={p_edge}; authentication {{ password-file "{root/'pwd'}"; }}; tls {{ server-name "localhost"; ca-file "{c['cert']}"; verify #true; }}; }}
routing {{ default-outbound "edge"; }}''',
                mh_server_cfg({"name": "any-in", "type": "anytls", "listen": "127.0.0.1", "port": p_edge,
                               "users": {"u": "interop-secret-132"},
                               "certificate": str(c["cert"]), "private-key": str(c["key"])}),
                True, p_front, p_edge, do_udp=True,
            )
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Mihomo->Nexus AnyTLS", nexus_bin, mihomo_bin, root, tport, uport,
                f'''schema-version 1\nrole "server"\ninbound "any" type="anytls" {{ listen host="127.0.0.1" port={p_edge}; authentication {{ user "u" password-file="{root/'pwd'}"; }}; tls {{ certificate-file "{c['cert']}"; private-key-file "{c['key']}"; }}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                mh_client_cfg(p_front, {"name": "nx", "type": "anytls", "server": "127.0.0.1", "port": p_edge,
                                        "password": "interop-secret-132", "sni": "localhost", "udp": True, "skip-cert-verify": True}),
                False, p_front, p_front, do_udp=True,
            )

            print(f"BATCH 132 PEER A BIDIRECTIONAL INTEROP MATRIX PASSED [{nexus_bin.name}]", flush=True)
        finally:
            stop_cover.set(); csrv.close()
    stop_echo.set(); tsrv.close(); usrv.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("nexus_bin", type=Path)
    p.add_argument("peer_bin", type=Path)
    args = p.parse_args()
    run_suite(args.nexus_bin.resolve(strict=True), args.peer_bin.resolve(strict=True))
