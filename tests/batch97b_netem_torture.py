#!/usr/bin/env python3
"""Batch 97B: Isolated netns tc netem weak-network torture (loss/jitter/corrupt, reorder/dup, MTU 1280, reload/soak)."""
import argparse
import base64
import hashlib
import json
import os
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from detour_network import exact, reserve, socks
from dns_rule_support import nexus_process, udp_client
from tuic_singbox import REVISION, launch_singbox, stop_proc

CLI_IP = "10.97.0.1"
SRV_IP = "10.97.0.2"
XRAY_BIN = Path(__file__).resolve().parents[1] / "target/batch94a/xray-pinned"


def run_cmd(*args):
    subprocess.run(list(args), check=True, capture_output=True, text=True)


def setup_veth_pair():
    run_cmd("ip", "link", "set", "lo", "up")
    run_cmd("ip", "link", "add", "veth-cli", "type", "veth", "peer", "name", "veth-srv")
    run_cmd("ip", "addr", "add", f"{CLI_IP}/24", "dev", "veth-cli")
    run_cmd("ip", "addr", "add", f"{SRV_IP}/24", "dev", "veth-srv")
    run_cmd("ip", "link", "set", "veth-cli", "up")
    run_cmd("ip", "link", "set", "veth-srv", "up")


def set_netem(*spec):
    for dev in ("veth-cli", "veth-srv"):
        run_cmd("tc", "qdisc", "replace", "dev", dev, "root", "netem", *spec)


def clear_netem():
    for dev in ("veth-cli", "veth-srv"):
        subprocess.run(["tc", "qdisc", "del", "dev", dev, "root"], capture_output=True)


def set_mtu(mtu):
    for dev in ("veth-cli", "veth-srv"):
        run_cmd("ip", "link", "set", "dev", dev, "mtu", str(mtu))


def start_echo_on(host):
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((host, 0))
    tcp.listen(64)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((host, 0))
    stop = threading.Event()
    def handle_tcp(c):
        with c:
            c.settimeout(15)
            try:
                while data := c.recv(65536):
                    c.sendall(data)
            except OSError:
                pass
    def serve_tcp():
        tcp.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = tcp.accept()
                threading.Thread(target=handle_tcp, args=(c,), daemon=True).start()
            except TimeoutError:
                pass
            except OSError:
                break
    def serve_udp():
        udp.settimeout(0.2)
        while not stop.is_set():
            try:
                data, peer = udp.recvfrom(65535)
                udp.sendto(data, peer)
            except TimeoutError:
                pass
            except OSError:
                break
    threading.Thread(target=serve_tcp, daemon=True).start()
    threading.Thread(target=serve_udp, daemon=True).start()
    return tcp, tcp.getsockname()[1], udp, udp.getsockname()[1], stop


def make_cert(root):
    cert, key = root / "srv.crt", root / "srv.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
        "-addext", f"subjectAltName=DNS:localhost,IP:{SRV_IP},IP:127.0.0.1", "-days", "1",
    ], check=True, capture_output=True)
    key.chmod(0o600)
    return cert, key


def transfer_tcp(proxy_port, dst_host, dst_port, size):
    payload = os.urandom(size)
    with socks(proxy_port, 1, (dst_host, dst_port))[0] as c:
        c.settimeout(25)
        c.sendall(payload)
        c.shutdown(socket.SHUT_WR)
        got = exact(c, size)
        assert hashlib.sha256(got).digest() == hashlib.sha256(payload).digest(), "TCP digest mismatch"


def transfer_udp_burst(proxy_port, dst_host, dst_port, count=20, min_received=12):
    received = 0
    with udp_client(proxy_port) as (u, relay):
        u.settimeout(0.5)
        for i in range(count):
            tag = f"udp-{i:03d}-".encode() + b"x" * 120
            pkt = b"\x00\x00\x00\x01" + socket.inet_aton(dst_host) + struct.pack("!H", dst_port) + tag
            u.sendto(pkt, relay)
            try:
                rx, _ = u.recvfrom(4096)
                if rx[10:] == tag:
                    received += 1
            except TimeoutError:
                pass
    assert received >= min_received, f"UDP burst too low: {received}/{count}"
    return received


def run_loss_jitter_corrupt(binary, root, cert, key, tp, up):
    set_netem("delay", "35ms", "12ms", "loss", "5%", "corrupt", "0.1%")
    pwd = root / "pwd"; pwd.write_text("netem-secret\n"); pwd.chmod(0o600)
    uid = "00010203-0405-0607-0809-0a0b0c0d0e0f"
    uidf = root / "uid"; uidf.write_text(uid + "\n"); uidf.chmod(0o600)
    tr_p, hy_p, tu_p = reserve(), reserve(), reserve()

    sb_cfg = root / "sb_netem.json"
    sb_cfg.write_text(json.dumps({
        "log": {"level": "error"},
        "inbounds": [
            {"type": "trojan", "listen": SRV_IP, "listen_port": tr_p, "users": [{"password": "netem-secret"}],
             "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}},
            {"type": "hysteria2", "listen": SRV_IP, "listen_port": hy_p,
             "users": [{"name": "u", "password": "netem-secret"}],
             "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key), "alpn": ["h3"]}},
            {"type": "tuic", "listen": SRV_IP, "listen_port": tu_p,
             "users": [{"name": "u", "uuid": uid, "password": "netem-secret"}], "congestion_control": "bbr",
             "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key), "alpn": ["h3"]}},
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }))
    sb = launch_singbox(sb_cfg)
    try:
        for proto, out_kdl, do_udp in (
            ("trojan", f'outbound "edge" type="trojan" {{ server host="{SRV_IP}" port={tr_p}; authentication {{ password-file "{pwd}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}; }}', False),
            ("hysteria2", f'outbound "edge" type="hysteria2" {{ server host="{SRV_IP}" port={hy_p}; authentication {{ password-file "{pwd}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}; }}', True),
            ("tuic", f'outbound "edge" type="tuic" {{ server host="{SRV_IP}" port={tu_p}; congestion-control "bbr"; authentication {{ uuid-file "{uidf}"; password-file "{pwd}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}; }}', True),
        ):
            front = reserve()
            cfg = root / f"nx_{proto}.kdl"
            cfg.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{ inet4-bind-address "{CLI_IP}"; }}
{out_kdl}
routing {{ final "edge"; }}
''')
            with nexus_process(str(binary), str(cfg)):
                transfer_tcp(front, SRV_IP, tp, 131072)
                if do_udp:
                    transfer_udp_burst(front, SRV_IP, up, count=16, min_received=8)
    finally:
        stop_proc(sb)

    # Also test pinned Xray-core 26.3.27 VLESS XHTTP H2 under 5% loss!
    if XRAY_BIN.exists():
        xr_p, front = reserve(), reserve()
        xr_cfg = root / "xray_netem.json"
        xr_cfg.write_text(json.dumps({
            "log": {"loglevel": "error"},
            "inbounds": [{"listen": SRV_IP, "port": xr_p, "protocol": "vless",
                          "settings": {"decryption": "none", "clients": [{"id": uid}]},
                          "streamSettings": {"network": "xhttp", "security": "tls",
                                             "tlsSettings": {"alpn": ["h2"], "serverName": "localhost",
                                                             "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}]},
                                             "xhttpSettings": {"path": "/netem/", "mode": "stream-one"}}}],
            "outbounds": [{"protocol": "freedom"}],
        }))
        xr = subprocess.Popen([str(XRAY_BIN), "run", "-c", str(xr_cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(0.4)
        try:
            nx_xr = root / "nx_xray.kdl"
            nx_xr.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{ inet4-bind-address "{CLI_IP}"; }}
outbound "edge" type="vless" {{
    server host="{SRV_IP}" port={xr_p}
    authentication {{ uuid-file "{uidf}"; }}
    tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}
    transport "xhttp" {{ protocol "h2"; mode "stream-one"; path "/netem/"; }}
}}
routing {{ final "edge"; }}
''')
            with nexus_process(str(binary), str(nx_xr)):
                transfer_tcp(front, SRV_IP, tp, 131072)
        finally:
            stop_proc(xr)
    print("97B.1 loss 5% + delay 35ms±12ms + corrupt 0.1% (Trojan/Hy2/TUIC/Xray-XHTTP) passed")


def run_reorder_dup_and_mtu1280(binary, root, cert, key, tp, up):
    set_netem("delay", "20ms", "6ms", "reorder", "15%", "50%", "duplicate", "2%")
    psk = base64.b64encode(bytes(range(16))).decode()
    (root / "psk").write_text(psk + "\n"); (root / "psk").chmod(0o600)
    ss_p, front = reserve(), reserve()
    sb_cfg = root / "sb_ss_reorder.json"
    sb_cfg.write_text(json.dumps({
        "log": {"level": "error"},
        "inbounds": [{"type": "shadowsocks", "listen": SRV_IP, "listen_port": ss_p,
                      "method": "2022-blake3-aes-128-gcm", "password": psk}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }))
    nx_cfg = root / "nx_ss_reorder.kdl"
    nx_cfg.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{ inet4-bind-address "{CLI_IP}"; }}
outbound "edge" type="shadowsocks" {{
    server host="{SRV_IP}" port={ss_p}; method "2022-blake3-aes-128-gcm"; key-file "{root / 'psk'}"; udp-over-tcp "v2";
}}
routing {{ final "edge"; }}
''')
    sb = launch_singbox(sb_cfg)
    try:
        with nexus_process(str(binary), str(nx_cfg)):
            transfer_tcp(front, SRV_IP, tp, 131072)
            transfer_udp_burst(front, SRV_IP, up, count=20, min_received=16)
    finally:
        stop_proc(sb)

    # Low MTU 1280 B blackhole test (Hy2 QUIC + Trojan TLS)
    clear_netem()
    set_mtu(1280)
    set_netem("delay", "15ms", "loss", "1%")
    pwd = root / "pwd"
    hy_p, tr_p = reserve(), reserve()
    sb_mtu = root / "sb_mtu.json"
    sb_mtu.write_text(json.dumps({
        "log": {"level": "error"},
        "inbounds": [
            {"type": "hysteria2", "listen": SRV_IP, "listen_port": hy_p,
             "users": [{"name": "u", "password": "netem-secret"}],
             "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key), "alpn": ["h3"]}},
            {"type": "trojan", "listen": SRV_IP, "listen_port": tr_p, "users": [{"password": "netem-secret"}],
             "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}},
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }))
    sb = launch_singbox(sb_mtu)
    try:
        for proto, out_kdl in (
            ("hy2", f'outbound "edge" type="hysteria2" {{ server host="{SRV_IP}" port={hy_p}; authentication {{ password-file "{pwd}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}; }}'),
            ("tr", f'outbound "edge" type="trojan" {{ server host="{SRV_IP}" port={tr_p}; authentication {{ password-file "{pwd}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}; }}'),
        ):
            f2 = reserve()
            c2 = root / f"nx_mtu_{proto}.kdl"
            c2.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={f2}; authentication "none"; }}
outbound "direct" type="direct" {{ inet4-bind-address "{CLI_IP}"; }}
{out_kdl}
routing {{ final "edge"; }}
''')
            with nexus_process(str(binary), str(c2)):
                transfer_tcp(f2, SRV_IP, tp, 196608)
    finally:
        stop_proc(sb)
        clear_netem()
        set_mtu(1500)
    print("97B.2 reorder 15%/dup 2% (SS-2022) + MTU 1280 blackhole (Hy2/Trojan) passed")


def run_reload_halfdead_leak_soak(binary, root, tp):
    set_netem("delay", "15ms", "loss", "2%")
    front, ctrl = reserve(), reserve()
    cfg = root / "soak.kdl"
    cfg.write_text(f'''schema-version 1
role "client"
workers 2
control http-listen="127.0.0.1:{ctrl}" metrics=#true
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{ inet4-bind-address "{CLI_IP}"; }}
routing {{ final "direct"; }}
''')
    proc = subprocess.Popen([str(binary), "run", "--config", str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 8
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"soak proxy exited {proc.returncode}: {proc.stderr.read()!r}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{ctrl}/v1/health", timeout=1) as r:
                    if r.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.05)
        assert ready, "soak control HTTP did not become ready"
        fd_base = len(os.listdir(f"/proc/{proc.pid}/fd"))

        def worker_flow(i):
            if i % 4 == 0:
                # Intentional abrupt half-dead RST drop mid-flight!
                s = socks(front, 1, (SRV_IP, tp))[0]
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                s.sendall(os.urandom(4096))
                s.close()
            else:
                transfer_tcp(front, SRV_IP, tp, 16384)

        for r_idx in range(3):
            with ThreadPoolExecutor(max_workers=12) as pool:
                list(pool.map(worker_flow, range(16)))
            if r_idx < 2:
                proc.send_signal(signal.SIGHUP)
                time.sleep(0.3)
            with urllib.request.urlopen(f"http://127.0.0.1:{ctrl}/metrics", timeout=3) as resp:
                body = resp.read()
                assert b"nexus_control_generation" in body and b"nexus_active_sessions" in body, body

        time.sleep(1.0)
        with urllib.request.urlopen(f"http://127.0.0.1:{ctrl}/metrics", timeout=3) as resp:
            final_metrics = resp.read().decode("utf-8", errors="replace")
            assert 'nexus_active_sessions{listener="0"} 0' in final_metrics, final_metrics
        fd_after = len(os.listdir(f"/proc/{proc.pid}/fd"))
        assert proc.poll() is None, "proxy died during soak"
        assert fd_after <= fd_base + 4, f"FD leak detected: base={fd_base}, after={fd_after}"
        print(f"97B.3 reload + abrupt RST + /metrics soak passed (fds base={fd_base} -> after={fd_after})")
    finally:
        clear_netem()
        stop_proc(proc)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("binary", type=Path)
    args = p.parse_args()
    assert f"Revision: {REVISION}" in subprocess.check_output(["sing-box", "version"], text=True)
    setup_veth_pair()
    tcp, tp, udp, up, stop = start_echo_on(SRV_IP)
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-batch97b-") as d:
            root = Path(d)
            cert, key = make_cert(root)
            run_loss_jitter_corrupt(args.binary.resolve(), root, cert, key, tp, up)
            run_reorder_dup_and_mtu1280(args.binary.resolve(), root, cert, key, tp, up)
            run_reload_halfdead_leak_soak(args.binary.resolve(), root, tp)
    finally:
        stop.set(); tcp.close(); udp.close()
    print("ALL BATCH 97B NETEM WEAK-NETWORK TORTURE TESTS PASSED")


if __name__ == "__main__":
    main()
