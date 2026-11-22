#!/usr/bin/env python3
"""Bidirectional TUIC v5 (TCP + UDP, native/over-stream, uTLS) interop against sing-box."""
import argparse
from tuic_udp_isolation_support import exercise_udp_isolation
from dns_rule_support import exact
import json
import os
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

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


def start_udp_echo():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                data, peer = srv.recvfrom(65535)
                srv.sendto(data, peer)
            except TimeoutError:
                pass
            except OSError:
                break

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return srv, srv.getsockname()[1], stop


def launch_nexus(nexus_bin, cfg_path, ready_prefix):
    proc = subprocess.Popen(
        ["stdbuf", "-oL", nexus_bin, "run", "--config", str(cfg_path)],
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


def launch_singbox(cfg_path, tcp_check_port=None):
    subprocess.run(["sing-box", "check", "-c", str(cfg_path)], check=True, capture_output=True, text=True)
    proc = subprocess.Popen(
        ["sing-box", "run", "-c", str(cfg_path)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"sing-box exited early:\n{proc.stdout.read()}")
        if tcp_check_port is None:
            time.sleep(0.35)
            return proc
        try:
            with socket.create_connection(("127.0.0.1", tcp_check_port), timeout=0.2):
                return proc
        except OSError:
            time.sleep(0.05)
    proc.kill()
    raise RuntimeError(f"sing-box startup timeout:\n{proc.stdout.read()}")


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


def socks5_udp_echo(proxy_port, dst_host, dst_port, payload):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(8)
    ctrl = socket.create_connection(("127.0.0.1", proxy_port), timeout=8)
    try:
        ctrl.sendall(b"\x05\x01\x00")
        if ctrl.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 UDP greeting rejected")
        ctrl.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.getsockname()[1]))
        rep = ctrl.recv(10)
        if len(rep) != 10 or rep[1] != 0 or rep[3] != 1:
            raise RuntimeError(f"SOCKS5 UDP ASSOCIATE failed: {rep!r}")
        relay_port = struct.unpack("!H", rep[8:10])[0]
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton(dst_host) + struct.pack("!H", dst_port) + payload
        udp.sendto(pkt, ("127.0.0.1", relay_port))
        rx, _ = udp.recvfrom(65535)
        if rx[10:] != payload:
            raise RuntimeError(f"SOCKS5 UDP echo mismatch: {rx!r}")
    finally:
        udp.close()
        ctrl.close()


def stop_proc(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def run_interop(nexus_bin, isolate_udp=False, recover=False):
    ver = subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout
    if f"Revision: {REVISION}" not in ver:
        raise RuntimeError(f"unexpected sing-box revision:\n{ver}")

    for controller in ("bbr", "cubic"):
        print(f"TUIC v5 interoperability with {controller} on both peers", flush=True)
        run_controller(nexus_bin,controller,isolate_udp,recover)


def run_controller(nexus_bin,controller,isolate_udp,recover):
    tcp_srv, tcp_port, tcp_stop = start_tcp_echo()
    udp_srv, udp_port, udp_stop = start_udp_echo()
    with tempfile.TemporaryDirectory(prefix="nexus-tuic-sb-") as tmp:
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
        uid = "b7c2f3e8-1d44-4a5b-9e6c-0a1b2c3d4e5f"
        pwd = "tuic-interop-secret"
        uuid_f = root / "uuid.txt"
        uuid_f.write_text(uid + "\n")
        os.chmod(uuid_f, 0o600)
        pass_f = root / "pass.txt"
        pass_f.write_text(pwd + "\n")
        os.chmod(pass_f, 0o600)

        procs = []
        try:
            # 1. Nexus Client (uTLS chrome native, uTLS safari udp-over-stream) -> sing-box Server
            sb_tuic_port = free_port(socket.SOCK_DGRAM)
            sb_srv_cfg = root / "sb_tuic_srv.json"
            sb_srv_cfg.write_text(json.dumps({
                "log": {"level": "warn"},
                "inbounds": [{
                    "type": "tuic", "tag": "tuic-in",
                    "listen": "127.0.0.1", "listen_port": sb_tuic_port,
                    "users": [{"name": "u1", "uuid": uid, "password": pwd}],
                    "congestion_control": controller,
                    "tls": {"enabled": True, "server_name": "localhost", "alpn": ["h3"], "certificate_path": str(cert), "key_path": str(key)},
                }],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"final": "direct"},
            }))
            sb_srv = launch_singbox(sb_srv_cfg)
            procs.append(sb_srv)

            for fp, uos in (("chrome", "#false"), ("safari", "#true")):
                socks_port = free_port()
                nx_cli_cfg = root / f"nx_tuic_cli_{fp}.kdl"
                idle = ""
                if recover:
                    idle = f"idle-timeout-ms 400; udp-bind-port {free_port(socket.SOCK_DGRAM)};"
                    if fp == "safari":
                        idle += " heartbeat-ms 100;"
                nx_cli_cfg.write_text(f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={socks_port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "tuic-out" type="tuic" {{
    server host="127.0.0.1" port={sb_tuic_port}
    congestion-control "{controller}"
    udp-over-stream {uos}
    {idle}
    authentication {{ uuid-file "{uuid_f}"; password-file "{pass_f}"; }}
    tls {{ server-name "localhost"; ca-file "{cert}"; fingerprint "{fp}"; verify #true; }}
}}
routing {{ default-outbound "tuic-out"; }}
''')
                c_proc, c_port = launch_nexus(nexus_bin, nx_cli_cfg, "SOCKS5 listening on ")
                try:
                    socks5_tcp_echo(c_port, "127.0.0.1", tcp_port, f"nx-tuic-tcp-{fp}".encode() * 16)
                    socks5_udp_echo(c_port, "127.0.0.1", udp_port, f"nx-tuic-udp-{fp}".encode())
                    if isolate_udp:
                        exercise_udp_isolation(c_port,fp)
                    if recover and fp == "safari":
                        with socket.create_connection(("127.0.0.1", c_port), timeout=3) as client:
                            client.sendall(b"\x05\x01\x00")
                            assert exact(client, 2) == b"\x05\x00"
                            client.sendall(b"\x05\x01\x00\x01\x7f\0\0\x01" + struct.pack("!H", tcp_port))
                            assert exact(client, 10)[:2] == b"\x05\x00"
                            client.sendall(b"before-idle")
                            assert exact(client, 11) == b"before-idle"
                            time.sleep(1.6)
                            client.sendall(b"after-idle")
                            assert exact(client, 10) == b"after-idle"
                        print("TUIC configured QUIC keepalive preserved an existing TCP stream across idle time")
                    elif recover:
                        time.sleep(1.6)
                        socks5_tcp_echo(c_port, "127.0.0.1", tcp_port, b"new-tuic-after-idle")
                        socks5_udp_echo(c_port, "127.0.0.1", udp_port, b"udp-after-idle")
                        print("TUIC recovered expired connection with the same configured UDP port")
                finally:
                    stop_proc(c_proc)
            print("Interop Nexus Client (TUIC v5 uTLS chrome native + safari udp-over-stream) -> sing-box Server passed")

            # 2. sing-box Client (native & quic stream UDP) -> Nexus Server
            nx_tuic_port = free_port(socket.SOCK_DGRAM)
            nx_srv_cfg = root / "nx_tuic_srv.kdl"
            nx_srv_cfg.write_text(f'''schema-version 1
role "server"
inbound "tuic-in" type="tuic" {{
    listen host="127.0.0.1" port={nx_tuic_port}
    congestion-control "{controller}"
    authentication {{ user "u1" uuid-file="{uuid_f}" password-file="{pass_f}"; }}
    tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
            nx_srv, actual_port = launch_nexus(nexus_bin, nx_srv_cfg, "TUIC listening on ")
            procs.append(nx_srv)

            for mode in ("native", "quic"):
                sb_socks_port = free_port()
                sb_cli_cfg = root / f"sb_tuic_cli_{mode}.json"
                sb_cli_cfg.write_text(json.dumps({
                    "log": {"level": "warn"},
                    "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": sb_socks_port}],
                    "outbounds": [{
                        "type": "tuic", "tag": "tuic-out",
                        "server": "127.0.0.1", "server_port": actual_port,
                        "uuid": uid, "password": pwd,
                        "congestion_control": controller, "udp_relay_mode": mode,
                        "tls": {"enabled": True, "server_name": "localhost", "alpn": ["h3"], "certificate_path": str(cert)},
                    }],
                    "route": {"final": "tuic-out"},
                }))
                sb_cli = launch_singbox(sb_cli_cfg, sb_socks_port)
                try:
                    socks5_tcp_echo(sb_socks_port, "127.0.0.1", tcp_port, f"sb-tuic-tcp-{mode}".encode() * 16)
                    socks5_udp_echo(sb_socks_port, "127.0.0.1", udp_port, f"sb-tuic-udp-{mode}".encode())
                finally:
                    stop_proc(sb_cli)
            print("Interop sing-box Client (TUIC v5 native + quic UDP) -> Nexus Server passed")
        finally:
            for p in reversed(procs):
                stop_proc(p)
            udp_stop.set()
            udp_srv.close()
            tcp_stop.set()
            tcp_srv.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("nexus_bin")
    parser.add_argument("--udp-isolation", action="store_true")
    parser.add_argument("--recover", action="store_true")
    args=parser.parse_args()
    run_interop(args.nexus_bin,args.udp_isolation,args.recover)
