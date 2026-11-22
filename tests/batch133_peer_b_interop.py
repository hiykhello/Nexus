#!/usr/bin/env python3
"""Batch 133: Bidirectional multi-protocol + full XHTTP interop torture between Nexus and Peer B (Xray)."""
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
from batch132_peer_a_interop import make_creds, start_echo_servers, start_tls_cover, stop_proc, verify_tcp, verify_udp

UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"


def launch_xray(xray_bin: Path, root: Path, name: str, cfg: dict, wait_tcp_port=None):
    cfg_path = root / f"xr-{name}.json"
    cfg_path.write_text(json.dumps(cfg))
    env = os.environ.copy()
    env["SSL_CERT_FILE"] = str(root / "cert.pem")
    proc = subprocess.Popen([str(xray_bin), "run", "-c", str(cfg_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"xray exited early ({name}): {proc.stdout.read()}")
        if wait_tcp_port is None:
            time.sleep(0.3)
            return proc
        try:
            with socket.create_connection(("127.0.0.1", wait_tcp_port), timeout=0.2):
                return proc
        except OSError:
            time.sleep(0.05)
    proc.kill()
    raise RuntimeError(f"xray startup timeout ({name}): {proc.stdout.read()}")


def run_case(label: str, nexus_bin: Path, xray_bin: Path, root: Path, tcp_port: int, udp_port: int,
             nx_cfg: str, xr_cfg: dict, nexus_is_client: bool, proxy_port: int, xr_wait_port, do_udp: bool = True):
    safe = label.replace(" ", "_").replace("/", "_").replace("+", "_")
    cfg_file = root / f"nx-{safe}.kdl"
    cfg_file.write_text(nx_cfg)
    if nexus_is_client:
        xr = launch_xray(xray_bin, root, safe, xr_cfg, xr_wait_port)
        try:
            with nexus_process(str(nexus_bin), str(cfg_file)):
                verify_tcp(proxy_port, tcp_port)
                if do_udp:
                    verify_udp(proxy_port, udp_port)
        finally:
            stop_proc(xr)
    else:
        with nexus_process(str(nexus_bin), str(cfg_file)):
            xr = launch_xray(xray_bin, root, safe, xr_cfg, xr_wait_port)
            try:
                verify_tcp(proxy_port, tcp_port)
                if do_udp:
                    verify_udp(proxy_port, udp_port)
            finally:
                stop_proc(xr)
    print(f"  [PASS] {label} (TCP{' + UDP' if do_udp else ''})", flush=True)


def start_go_tls_cover(root: Path, cert: Path, key: Path):
    go_cover = Path(__file__).resolve().parent / "batch94a_tls_cover.go"
    cover_bin = root / "tls-cover"
    subprocess.run(["go", "build", "-o", str(cover_bin), str(go_cover)], check=True, capture_output=True)
    port = reserve()
    proc = subprocess.Popen([str(cover_bin), f"127.0.0.1:{port}", str(cert), str(key), "hybrid"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return proc, port
        except OSError:
            time.sleep(0.025)
    stop_proc(proc)
    raise RuntimeError("Go TLS cover did not start")


def run_suite(nexus_bin: Path, xray_bin: Path):
    tsrv, tport, usrv, uport, stop_echo = start_echo_servers()
    with tempfile.TemporaryDirectory(prefix="nexus-b133-") as d:
        root = Path(d)
        c = make_creds(root)
        der = subprocess.check_output(["openssl", "x509", "-in", str(c["cert"]), "-outform", "DER"])
        cert_pin = hashlib.sha256(der).hexdigest()
        cover_proc, cover_port = start_go_tls_cover(root, c["cert"], c["key"])
        try:
            def xr_client(front, outbound):
                return {
                    "log": {"loglevel": "warning"},
                    "inbounds": [{"listen": "127.0.0.1", "port": front, "protocol": "socks",
                                  "settings": {"auth": "noauth", "udp": True}}],
                    "outbounds": [outbound],
                }

            def xr_server(inbound):
                return {
                    "log": {"loglevel": "warning"},
                    "inbounds": [inbound],
                    "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {
                        "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8", "::1/128"]}],
                    }}],
                }

            tls_srv = {"certificates": [{"certificateFile": str(c["cert"]), "keyFile": str(c["key"])}], "alpn": ["http/1.1"]}
            tls_cli = {"serverName": "localhost", "pinnedPeerCertSha256": cert_pin}

            # 1. Trojan (TCP + UDP + TLS) — Bidirectional
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Nexus->Xray Trojan", nexus_bin, xray_bin, root, tport, uport,
                f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="trojan" {{ server host="127.0.0.1" port={p_edge}; authentication {{ password-file "{root/'pwd'}"; }}; tls {{ server-name "localhost"; ca-file "{c['cert']}"; verify #true; }}; }}
routing {{ default-outbound "edge"; }}''',
                xr_server({"listen": "127.0.0.1", "port": p_edge, "protocol": "trojan",
                           "settings": {"clients": [{"password": "interop-secret-132"}]},
                           "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": tls_srv}}),
                True, p_front, p_edge, do_udp=True,
            )
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Xray->Nexus Trojan", nexus_bin, xray_bin, root, tport, uport,
                f'''schema-version 1\nrole "server"\ninbound "tr" type="trojan" {{ listen host="127.0.0.1" port={p_edge}; authentication {{ user "u" password-file="{root/'pwd'}"; }}; tls {{ certificate-file "{c['cert']}"; private-key-file "{c['key']}"; }}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                xr_client(p_front, {"protocol": "trojan", "settings": {"servers": [{"address": "127.0.0.1", "port": p_edge, "password": "interop-secret-132"}]},
                                    "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": tls_cli}}),
                False, p_front, p_front, do_udp=True,
            )

            # 2. Shadowsocks 2022 (AES-128 & AES-256) — Bidirectional
            for method, psk_name, psk_val in (("2022-blake3-aes-128-gcm", "psk128", c["psk128"]),
                                              ("2022-blake3-aes-256-gcm", "psk256", c["psk256"])):
                p_edge, p_front = reserve(), reserve()
                run_case(
                    f"Nexus->Xray SS2022-{method[-11:-4]}", nexus_bin, xray_bin, root, tport, uport,
                    f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={p_edge}; method "{method}"; key-file "{root/psk_name}"; }}
routing {{ default-outbound "edge"; }}''',
                    xr_server({"listen": "127.0.0.1", "port": p_edge, "protocol": "shadowsocks",
                               "settings": {"method": method, "password": psk_val, "network": "tcp,udp"}}),
                    True, p_front, p_edge, do_udp=False,
                )
                p_edge, p_front = reserve(), reserve()
                run_case(
                    f"Xray->Nexus SS2022-{method[-11:-4]}", nexus_bin, xray_bin, root, tport, uport,
                    f'''schema-version 1\nrole "server"\ninbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={p_edge}; method "{method}"; key-file "{root/psk_name}"; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                    xr_client(p_front, {"protocol": "shadowsocks", "settings": {"servers": [{"address": "127.0.0.1", "port": p_edge, "method": method, "password": psk_val}]}}),
                    False, p_front, p_front, do_udp=True,
                )

            # 3. VLESS + TLS + XTLS-Vision — Bidirectional
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Nexus->Xray VLESS+Vision", nexus_bin, xray_bin, root, tport, uport,
                f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={p_edge}; flow "xtls-rprx-vision"; authentication {{ uuid-file "{root/'uuid'}"; }}; tls {{ server-name "localhost"; ca-file "{c['cert']}"; verify #true; }}; }}
routing {{ default-outbound "edge"; }}''',
                xr_server({"listen": "127.0.0.1", "port": p_edge, "protocol": "vless",
                           "settings": {"decryption": "none", "clients": [{"id": UUID, "flow": "xtls-rprx-vision"}]},
                           "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": tls_srv}}),
                True, p_front, p_edge, do_udp=True,
            )
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Xray->Nexus VLESS+Vision", nexus_bin, xray_bin, root, tport, uport,
                f'''schema-version 1\nrole "server"\ninbound "vl" type="vless" {{ listen host="127.0.0.1" port={p_edge}; flow "xtls-rprx-vision"; authentication {{ user "u" uuid-file="{root/'uuid'}"; }}; tls {{ certificate-file "{c['cert']}"; private-key-file "{c['key']}"; }}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                xr_client(p_front, {"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": p_edge, "users": [{"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
                                    "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": tls_cli}}),
                False, p_front, p_front, do_udp=True,
            )

            # 4. VLESS + REALITY + Vision (+ X25519MLKEM768) — Bidirectional
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Nexus->Xray VLESS+REALITY+Vision+MLKEM", nexus_bin, xray_bin, root, tport, uport,
                f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={p_edge}; flow "xtls-rprx-vision"; authentication {{ uuid-file "{root/'uuid'}"; }}; tls {{ server-name "localhost"; fingerprint "chrome"; key-exchange "x25519-mlkem768"; reality {{ public-key "{c['pub'].hex()}"; short-id "{SHORT}"; }}; }}; }}
routing {{ default-outbound "edge"; }}''',
                xr_server({"listen": "127.0.0.1", "port": p_edge, "protocol": "vless",
                           "settings": {"decryption": "none", "clients": [{"id": UUID, "flow": "xtls-rprx-vision"}]},
                           "streamSettings": {"network": "raw", "security": "reality",
                                              "realitySettings": {"target": f"127.0.0.1:{cover_port}", "serverNames": ["localhost"],
                                                                  "privateKey": b64url(c["seed"]), "shortIds": [SHORT]}}}),
                True, p_front, p_edge, do_udp=True,
            )
            p_edge, p_front = reserve(), reserve()
            run_case(
                "Xray->Nexus VLESS+REALITY+Vision", nexus_bin, xray_bin, root, tport, uport,
                f'''schema-version 1\nrole "server"\ninbound "vl" type="vless" {{ listen host="127.0.0.1" port={p_edge}; flow "xtls-rprx-vision"; authentication {{ user "u" uuid-file="{root/'uuid'}"; }}; tls {{ reality {{ private-key-file "{root/'rkey'}"; server-name "localhost"; short-id "{SHORT}"; max-time-difference 15; fallback host="127.0.0.1" port={cover_port}; }}; }}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                xr_client(p_front, {"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": p_edge, "users": [{"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
                                    "streamSettings": {"network": "raw", "security": "reality",
                                                       "realitySettings": {"serverName": "localhost", "fingerprint": "chrome",
                                                                           "password": b64url(c["pub"]), "shortId": SHORT}}}),
                False, p_front, p_front, do_udp=True,
            )

            # 5. VLESS + WebSocket / HTTPUpgrade / gRPC — Bidirectional
            for net_name, nx_tr, xr_stream in (
                ("WS", 'transport "websocket" { host "localhost"; path "/ws"; }',
                 {"network": "ws", "wsSettings": {"path": "/ws", "host": "localhost"}}),
                ("HTTPUpgrade", 'transport "httpupgrade" { host "localhost"; path "/up"; }',
                 {"network": "httpupgrade", "httpupgradeSettings": {"path": "/up", "host": "localhost"}}),
                ("gRPC", 'transport "grpc" { service-name "nexus.Grpc"; authority "localhost"; }',
                 {"network": "grpc", "grpcSettings": {"serviceName": "nexus.Grpc", "authority": "localhost"}}),
            ):
                p_edge, p_front = reserve(), reserve()
                srv_tls = dict(tls_srv, alpn=["h2"] if net_name == "gRPC" else ["http/1.1"])
                cli_tls = dict(tls_cli, alpn=["h2"] if net_name == "gRPC" else ["http/1.1"])
                run_case(
                    f"Nexus->Xray VLESS+{net_name}", nexus_bin, xray_bin, root, tport, uport,
                    f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={p_edge}; authentication {{ uuid-file "{root/'uuid'}"; }}; tls {{ server-name "localhost"; ca-file "{c['cert']}"; verify #true; }}; {nx_tr}; }}
routing {{ default-outbound "edge"; }}''',
                    xr_server({"listen": "127.0.0.1", "port": p_edge, "protocol": "vless",
                               "settings": {"decryption": "none", "clients": [{"id": UUID}]},
                               "streamSettings": {**xr_stream, "security": "tls", "tlsSettings": srv_tls}}),
                    True, p_front, p_edge, do_udp=True,
                )
                p_edge, p_front = reserve(), reserve()
                run_case(
                    f"Xray->Nexus VLESS+{net_name}", nexus_bin, xray_bin, root, tport, uport,
                    f'''schema-version 1\nrole "server"\ninbound "vl" type="vless" {{ listen host="127.0.0.1" port={p_edge}; authentication {{ user "u" uuid-file="{root/'uuid'}"; }}; tls {{ certificate-file "{c['cert']}"; private-key-file "{c['key']}"; }}; {nx_tr}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                    xr_client(p_front, {"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": p_edge, "users": [{"id": UUID, "encryption": "none"}]}]},
                                        "streamSettings": {**xr_stream, "security": "tls", "tlsSettings": cli_tls}}),
                    False, p_front, p_front, do_udp=True,
                )

            # 6. Full XHTTP Matrix (H1/H2/H3 × packet-up / stream-one / stream-up) — Bidirectional!
            xhttp_profiles = (
                ("h1", "packet-up", "http/1.1"),
                ("h2", "packet-up", "h2"),
                ("h2", "stream-one", "h2"),
                ("h2", "stream-up", "h2"),
                ("h3", "packet-up", "h3"),
                ("h3", "stream-one", "h3"),
                ("h3", "stream-up", "h3"),
            )
            for proto, mode, alpn in xhttp_profiles:
                p_edge = reserve() if proto != "h3" else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                if isinstance(p_edge, socket.socket):
                    p_edge.bind(("127.0.0.1", 0)); port_num = p_edge.getsockname()[1]; p_edge.close(); p_edge = port_num
                p_front = reserve()
                nx_tr = f'transport "xhttp" {{ protocol "{proto}"; mode "{mode}"; path "/edge/"; }}'
                xr_tr = {"network": "xhttp", "security": "tls", "xhttpSettings": {"path": "/edge/", "mode": mode}}
                run_case(
                    f"Nexus->Xray XHTTP-{proto}-{mode}", nexus_bin, xray_bin, root, tport, uport,
                    f'''schema-version 1\nrole "client"\ninbound "in" type="socks5" {{ listen host="127.0.0.1" port={p_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={p_edge}; authentication {{ uuid-file "{root/'uuid'}"; }}; tls {{ server-name "localhost"; ca-file "{c['cert']}"; verify #true; }}; {nx_tr}; }}
routing {{ default-outbound "edge"; }}''',
                    xr_server({"listen": "127.0.0.1", "port": p_edge, "protocol": "vless",
                               "settings": {"decryption": "none", "clients": [{"id": UUID}]},
                               "streamSettings": {**xr_tr, "tlsSettings": {**tls_srv, "alpn": [alpn]}}}),
                    True, p_front, p_edge if proto != "h3" else None, do_udp=False,
                )
                p_edge = reserve() if proto != "h3" else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                if isinstance(p_edge, socket.socket):
                    p_edge.bind(("127.0.0.1", 0)); port_num = p_edge.getsockname()[1]; p_edge.close(); p_edge = port_num
                p_front = reserve()
                run_case(
                    f"Xray->Nexus XHTTP-{proto}-{mode}", nexus_bin, xray_bin, root, tport, uport,
                    f'''schema-version 1\nrole "server"\ninbound "vl" type="vless" {{ listen host="127.0.0.1" port={p_edge}; authentication {{ user "u" uuid-file="{root/'uuid'}"; }}; tls {{ certificate-file "{c['cert']}"; private-key-file "{c['key']}"; }}; {nx_tr}; }}
outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}''',
                    xr_client(p_front, {"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": p_edge, "users": [{"id": UUID, "encryption": "none"}]}]},
                                        "streamSettings": {**xr_tr, "tlsSettings": {**tls_cli, "alpn": [alpn]}}}),
                    False, p_front, p_front, do_udp=False,
                )

            print(f"BATCH 133 PEER B BIDIRECTIONAL + FULL XHTTP INTEROP MATRIX PASSED [{nexus_bin.name}]", flush=True)
        finally:
            stop_proc(cover_proc)
    stop_echo.set(); tsrv.close(); usrv.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("nexus_bin", type=Path)
    p.add_argument("peer_bin", type=Path)
    args = p.parse_args()
    run_suite(args.nexus_bin.resolve(strict=True), args.peer_bin.resolve(strict=True))
