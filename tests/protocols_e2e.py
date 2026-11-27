#!/usr/bin/env python3
import argparse
import os
import selectors
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
from pathlib import Path


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
                    data = conn.recv(4096)
                except OSError:
                    break
                if not data:
                    break
                conn.sendall(data)

    def serve():
        srv.settimeout(0.1)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
            except TimeoutError:
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return srv, srv.getsockname()[1], stop


def start_udp_echo():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(0.1)
    stop = threading.Event()

    def serve():
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


def start_tls13_cover(cert_file, key_file):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("127.0.0.1", 0))
    raw.listen(16)
    raw.settimeout(0.1)
    stop = threading.Event()

    def handle(c):
        try:
            with ctx.wrap_socket(c, server_side=True) as tls:
                tls.settimeout(2.0)
                tls.sendall(b"COVER-TLS13-OK")
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def serve():
        while not stop.is_set():
            try:
                c, _ = raw.accept()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
            except TimeoutError:
                pass
            except OSError:
                break

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return raw, raw.getsockname()[1], stop


def launch_nexus(binary, config_path, prefix):
    proc = subprocess.Popen(
        ["stdbuf", "-oL", binary, "run", "--config", str(config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    deadline_lines = []
    for _ in range(20):
        if not sel.select(5):
            break
        line = proc.stdout.readline()
        if not line:
            break
        line = line.strip()
        deadline_lines.append(line)
        if line.startswith(prefix):
            port = int(line.rsplit(":", 1)[1])
            return proc, port
    out = "\n".join(deadline_lines)
    proc.kill()
    proc.wait()
    raise RuntimeError(f"failed starting nexus ({prefix}):\n{out}")


def socks5_tcp_connect(proxy_port, dst_host, dst_port):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 greeting rejected")
    ip = socket.inet_aton(dst_host)
    req = b"\x05\x01\x00\x01" + ip + struct.pack("!H", dst_port)
    s.sendall(req)
    rep = s.recv(10)
    if len(rep) < 4 or rep[1] != 0:
        raise RuntimeError(f"SOCKS5 CONNECT failed: {rep!r}")
    return s


def socks5_udp_roundtrip(proxy_port, dst_host, dst_port, payload):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(5)
    ctrl = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
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


def run_e2e(nexus_bin):
    tcp_srv, tcp_port, tcp_stop = start_tcp_echo()
    udp_srv, udp_port, udp_stop = start_udp_echo()
    with tempfile.TemporaryDirectory(prefix="nexus-proto-e2e-") as tmp:
        root = Path(tmp)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-keyout", str(key), "-out", str(cert),
                "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1",
            ],
            check=True, capture_output=True,
        )
        pass_f = root / "pass.txt"
        pass_f.write_text("e2e-secret\n")
        os.chmod(pass_f, 0o600)
        uuid_f = root / "uuid.txt"
        uuid_f.write_text("b7c2f3e8-1d44-4a5b-9e6c-0a1b2c3d4e5f\n")
        os.chmod(uuid_f, 0o600)
        bearer_f = root / "bearer.txt"
        bearer_f.write_text("e2e-bearer-token\n")
        os.chmod(bearer_f, 0o600)

        cover_srv, cover_port, cover_stop = start_tls13_cover(str(cert), str(key))
        procs = []
        try:
            # 1. ShadowTLS v3 (server + client with uTLS presets + cover fallback)
            stls_listen_port = free_port(socket.SOCK_STREAM)
            stls_srv_cfg = root / "stls_srv.kdl"
            stls_srv_cfg.write_text(f'''schema-version 1
role "server"
inbound "stls-in" type="shadowtls" {{
    listen host="127.0.0.1" port={stls_listen_port}
    handshake host="127.0.0.1" port={cover_port}
    target host="127.0.0.1" port={tcp_port}
    strict-tls13 #true
    authentication {{ user "u1" password-file="{pass_f}"; }}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
            s_proc, s_port = launch_nexus(nexus_bin, stls_srv_cfg, "ShadowTLS listening on ")
            procs.append(s_proc)

            for fp in ("chrome", "edge", "firefox", "safari", "ios", "android"):
                socks_listen_port = free_port(socket.SOCK_STREAM)
                stls_cli_cfg = root / f"stls_cli_{fp}.kdl"
                stls_cli_cfg.write_text(f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={socks_listen_port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "stls" type="shadowtls" {{
    server host="127.0.0.1" port={s_port}
    strict-tls13 #true
    authentication {{ password-file "{pass_f}"; }}
    tls {{ server-name "localhost"; ca-file "{cert}"; fingerprint "{fp}"; verify #true; }}
}}
routing {{ final "stls"; }}
''')
                c_proc, socks_port = launch_nexus(nexus_bin, stls_cli_cfg, "SOCKS5 listening on ")
                try:
                    with socks5_tcp_connect(socks_port, "127.0.0.1", tcp_port) as conn:
                        msg = f"stls-e2e-{fp}".encode()
                        conn.sendall(msg)
                        if conn.recv(64) != msg:
                            raise RuntimeError(f"ShadowTLS echo mismatch for {fp}")
                finally:
                    stop_proc(c_proc)

            # Plain TLS client passthrough through ShadowTLS cover fallback
            tls_ctx = ssl.create_default_context(cafile=str(cert))
            with socket.create_connection(("127.0.0.1", s_port), timeout=5) as raw_sock:
                with tls_ctx.wrap_socket(raw_sock, server_hostname="localhost") as tls_conn:
                    banner = tls_conn.recv(64)
                    if banner != b"COVER-TLS13-OK":
                        raise RuntimeError(f"ShadowTLS cover passthrough mismatch: {banner!r}")
            print("E2E ShadowTLS v3 + 6 uTLS presets + cover TLS 1.3 passthrough passed")

            # 2. TUIC v5 (server + client with uTLS firefox + TCP & UDP relay)
            tuic_listen_port = free_port(socket.SOCK_DGRAM)
            tuic_srv_cfg = root / "tuic_srv.kdl"
            tuic_srv_cfg.write_text(f'''schema-version 1
role "server"
inbound "tuic-in" type="tuic" {{
    listen host="127.0.0.1" port={tuic_listen_port}
    congestion-control "bbr"
    authentication {{ user "u1" uuid-file="{uuid_f}" password-file="{pass_f}"; }}
    tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
            t_proc, t_port = launch_nexus(nexus_bin, tuic_srv_cfg, "TUIC listening on ")
            procs.append(t_proc)

            tuic_socks_port = free_port(socket.SOCK_STREAM)
            tuic_cli_cfg = root / "tuic_cli.kdl"
            tuic_cli_cfg.write_text(f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={tuic_socks_port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "tuic-out" type="tuic" {{
    server host="127.0.0.1" port={t_port}
    congestion-control "bbr"
    authentication {{ uuid-file "{uuid_f}"; password-file "{pass_f}"; }}
    tls {{ server-name "localhost"; ca-file "{cert}"; fingerprint "firefox"; verify #true; }}
}}
routing {{ final "tuic-out"; }}
''')
            tc_proc, tc_socks = launch_nexus(nexus_bin, tuic_cli_cfg, "SOCKS5 listening on ")
            procs.append(tc_proc)
            with socks5_tcp_connect(tc_socks, "127.0.0.1", tcp_port) as conn:
                conn.sendall(b"tuic-tcp-e2e")
                if conn.recv(64) != b"tuic-tcp-e2e":
                    raise RuntimeError("TUIC TCP echo mismatch")
            socks5_udp_roundtrip(tc_socks, "127.0.0.1", udp_port, b"tuic-udp-e2e")
            print("E2E TUIC v5 + uTLS firefox (SOCKS5 TCP + UDP) passed")

            # 3. MASQUE Outbound (MASQUE server + client with uTLS safari + UDP relay)
            mq_listen_port = free_port(socket.SOCK_DGRAM)
            mq_srv_cfg = root / "mq_srv.kdl"
            mq_srv_cfg.write_text(f'''schema-version 1
role "server"
inbound "masque-in" type="masque" {{
    listen host="127.0.0.1" port={mq_listen_port}
    authority "localhost"
    authentication {{ bearer-file "{bearer_f}"; }}
    tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
    allow cidr="127.0.0.0/8" first-port=1 last-port=65535
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
            m_proc, m_port = launch_nexus(nexus_bin, mq_srv_cfg, "MASQUE listening on ")
            procs.append(m_proc)

            mq_socks_port = free_port(socket.SOCK_STREAM)
            mq_cli_cfg = root / "mq_cli.kdl"
            mq_cli_cfg.write_text(f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={mq_socks_port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "mq-out" type="masque" {{
    server host="127.0.0.1" port={m_port}
    authority "localhost"
    authentication {{ bearer-file "{bearer_f}"; }}
    tls {{ server-name "localhost"; ca-file "{cert}"; fingerprint "safari"; verify #true; }}
}}
routing {{ final "mq-out"; }}
''')
            mc_proc, mc_socks = launch_nexus(nexus_bin, mq_cli_cfg, "SOCKS5 listening on ")
            procs.append(mc_proc)
            socks5_udp_roundtrip(mc_socks, "127.0.0.1", udp_port, b"masque-udp-e2e")
            print("E2E MASQUE outbound + uTLS safari (SOCKS5 UDP CONNECT-UDP) passed")
        finally:
            for p in procs:
                stop_proc(p)
            cover_stop.set()
            cover_srv.close()
            tcp_stop.set()
            tcp_srv.close()
            udp_stop.set()
            udp_srv.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("nexus_bin")
    args = ap.parse_args()
    run_e2e(args.nexus_bin)
