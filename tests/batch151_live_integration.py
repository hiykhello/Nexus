#!/usr/bin/env python3
"""Batch 151 live end-to-end tests: Modern HTTP H2/H3/CONNECT-UDP + Bidirectional NaiveProxy."""
import argparse, concurrent.futures, os, pathlib, socket, ssl, struct, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent

def free_port(udp: bool = False) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def free_dual_port() -> int:
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ts:
            ts.bind(("127.0.0.1", 0))
            port = ts.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as us:
                try:
                    us.bind(("127.0.0.1", port))
                    return port
                except OSError:
                    continue

def find_nexus_bin(cli_arg: str | None) -> pathlib.Path:
    for p in [cli_arg, os.environ.get("NEXUS_BIN")]:
        if p and pathlib.Path(p).is_file():
            return pathlib.Path(p)
    for cand in sorted((ROOT / "target").glob("x86_64-linux-gnu/*/bin/nexus")):
        if cand.is_file():
            return cand
    raise FileNotFoundError("nexus binary not found; pass --nexus <path>")

def wait_tcp(port: int, proc: subprocess.Popen, name: str, timeout: float = 8.0) -> None:
    dl = time.monotonic() + timeout
    while time.monotonic() < dl:
        if proc.poll() is not None:
            o, e = proc.communicate()
            raise RuntimeError(f"{name} exited rc={proc.returncode}\n{o}\n{e}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.04)
    raise RuntimeError(f"timeout waiting for {name} on 127.0.0.1:{port}")

def stop_proc(proc: subprocess.Popen | None) -> None:
    if not proc or proc.poll() is not None:
        return
    proc.terminate()
    try:
        rc = proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait(timeout=2)
        return
    if rc < 0:
        raise RuntimeError(f"process {proc.args} crashed on shutdown with signal {-rc}")

class TcpEchoServer:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0)); self.sock.listen(64); self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop_ev = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(8.0)
            try:
                while data := conn.recv(16384):
                    conn.sendall(data)
            except OSError:
                pass

    def _run(self) -> None:
        while not self.stop_ev.is_set():
            try:
                c, _ = self.sock.accept()
                threading.Thread(target=self._handle, args=(c,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self) -> None:
        self.stop_ev.set(); self.sock.close()

class UdpEchoServer:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0)); self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop_ev = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        while not self.stop_ev.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
                self.sock.sendto(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self) -> None:
        self.stop_ev.set(); self.sock.close()

class HttpGetHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"nexus-h2-curl-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args) -> None: pass

def make_cert(d: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(key, 0o600)
    return cert, key

def write_kdl(path: pathlib.Path, content: str) -> pathlib.Path:
    path.write_text(content)
    return path

def write_pw(path: pathlib.Path, pw: str) -> pathlib.Path:
    path.write_text(pw); os.chmod(path, 0o600); return path

def start_nexus(nexus: pathlib.Path, cfg: pathlib.Path, tcp_port: int | None, name: str) -> subprocess.Popen:
    proc = subprocess.Popen([str(nexus), "run", "--config", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if tcp_port is not None:
        wait_tcp(tcp_port, proc, name)
    else:
        time.sleep(0.5)
        if proc.poll() is not None:
            o, e = proc.communicate()
            raise RuntimeError(f"{name} exited rc={proc.returncode}\n{o}\n{e}")
    return proc

def socks5_connect(proxy_port: int, dst_port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=8.0)
    s.settimeout(8.0)
    s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", dst_port))
    hdr = s.recv(10)
    if len(hdr) < 4 or hdr[1] != 0:
        s.close(); raise RuntimeError(f"SOCKS5 connect rejected: {hdr!r}")
    return s

def socks5_echo(proxy_port: int, dst_port: int, payload: bytes, byte_by_byte: bool = False) -> bytes:
    with socks5_connect(proxy_port, dst_port) as s:
        if byte_by_byte:
            for i in range(len(payload)):
                s.sendall(payload[i:i + 1]); time.sleep(0.002)
        else:
            s.sendall(payload)
        got = bytearray(); dl = time.monotonic() + 10.0
        while len(got) < len(payload) and time.monotonic() < dl:
            chunk = s.recv(len(payload) - len(got))
            if not chunk: break
            got.extend(chunk)
        return bytes(got)

def socks5_udp_echo(proxy_port: int, dst_port: int, payload: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=6.0) as ctrl:
        ctrl.settimeout(6.0)
        ctrl.sendall(b"\x05\x01\x00"); assert ctrl.recv(2) == b"\x05\x00"
        ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        rep = ctrl.recv(10)
        assert len(rep) == 10 and rep[1] == 0 and rep[3] == 1, f"bad udp rep: {rep!r}"
        bnd_port = struct.unpack("!H", rep[8:10])[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            u.settimeout(6.0)
            u.sendto(b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", dst_port) + payload,
                     ("127.0.0.1", bnd_port))
            resp, _ = u.recvfrom(4096)
            assert resp[:4] == b"\x00\x00\x00\x01"
            return resp[10:]

def run_h1_py_proxy(cert: pathlib.Path, key: pathlib.Path, port: int, stop_ev: threading.Event) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key)); ctx.set_alpn_protocols(["http/1.1"])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(16); srv.settimeout(0.2)

    def serve(raw: socket.socket) -> None:
        try:
            with ctx.wrap_socket(raw, server_side=True) as tls:
                buf = b""
                while b"\r\n\r\n" not in buf and len(buf) < 8192:
                    c = tls.recv(4096)
                    if not c: return
                    buf += c
                first_line = buf.split(b"\r\n", 1)[0].decode()
                method, target, _ = first_line.split(" ")
                if method == "CONNECT":
                    h, p = target.rsplit(":", 1)
                    up_sock = socket.create_connection((h, int(p)), timeout=5.0)
                    tls.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                else:
                    from urllib.parse import urlsplit
                    u = urlsplit(target)
                    up_sock = socket.create_connection((u.hostname, u.port or 80), timeout=5.0)
                    rest = buf.split(b"\r\n", 1)[1]
                    req_path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                    up_sock.sendall(f"{method} {req_path} HTTP/1.1\r\n".encode() + rest)
                with up_sock as up:
                    def pipe(a: socket.socket, b: socket.socket) -> None:
                        try:
                            while d := a.recv(8192): b.sendall(d)
                        except OSError: pass
                    t1 = threading.Thread(target=pipe, args=(tls, up), daemon=True)
                    t2 = threading.Thread(target=pipe, args=(up, tls), daemon=True)
                    t1.start(); t2.start(); t1.join(); t2.join()
        except OSError: pass

    def loop() -> None:
        try:
            while not stop_ev.is_set():
                try: threading.Thread(target=serve, args=(srv.accept()[0],), daemon=True).start()
                except socket.timeout: continue
        finally: srv.close()
    threading.Thread(target=loop, daemon=True).start()

def h2_decoy_probe(port: int, cert: pathlib.Path, headers_kv: list[tuple[str, str]]) -> tuple[str, bytes]:
    hpack = b"".join(b"\x00" + bytes([len(k.encode())]) + k.encode() + bytes([len(v.encode())]) + v.encode() for k, v in headers_kv)
    def frame(ft: int, fl: int, sid: int, pl: bytes) -> bytes:
        return struct.pack("!I", len(pl))[1:] + bytes([ft, fl]) + struct.pack("!I", sid) + pl
    ctx = ssl.create_default_context(cafile=str(cert)); ctx.set_alpn_protocols(["h2"])
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5.0), server_hostname="localhost") as tls:
        assert tls.selected_alpn_protocol() == "h2"
        tls.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b"") + frame(1, 0x05, 1, hpack))
        raw = bytearray(); dl = time.monotonic() + 4.0
        while time.monotonic() < dl:
            try:
                tls.settimeout(0.4); chunk = tls.recv(4096)
                if not chunk: break
                raw.extend(chunk)
                if b"<html" in raw.lower(): break
            except TimeoutError:
                if raw: break
        data = bytes(raw)
        assert b"407" not in data, f"Naive decoy MUST NOT contain 407, got {data!r}"
        low = data.lower()
        return ("200" if (b"welcome" in low or b"200" in data) else ("404" if (b"404 not found" in low or b"404" in data) else "other")), data

def suite_1_h2_proxy(nexus: pathlib.Path, d: pathlib.Path, echo_port: int, http_port: int, cert: pathlib.Path, key: pathlib.Path) -> None:
    pw = write_pw(d / "h2.pw", "pw151")
    sp_port, cp_port = free_port(), free_port()
    sp = start_nexus(nexus, write_kdl(d / "s1s.kdl", f'''schema-version 1; role "server"
inbound "h2-in" type="http" {{
    listen host="127.0.0.1" port={sp_port}; authentication "password" username="u" password-file="{pw}"
    tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}; http2 #true
}}
outbound "direct" type="direct"; routing {{ default-outbound "direct"; }}
'''), sp_port, "s1_srv")
    cp = start_nexus(nexus, write_kdl(d / "s1c.kdl", f'''schema-version 1; role "client"
inbound "s5" type="socks5" {{ listen host="127.0.0.1" port={cp_port}; authentication "none"; }}
outbound "hc" type="http-connect" {{
    http-version "h2"; server host="127.0.0.1" port={sp_port}; authentication username="u" password-file="{pw}"
    tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}
}}
outbound "direct" type="direct"; routing {{ default-outbound "hc"; }}
'''), cp_port, "s1_cli")
    try:
        payload = os.urandom(65536 + 123)
        assert socks5_echo(cp_port, echo_port, payload) == payload, "Suite 1 H2 CONNECT echo mismatch"
        ok = subprocess.run([
            "/usr/bin/curl", "-sS", "--proxy-http2", "--proxy", f"https://127.0.0.1:{sp_port}",
            "--proxy-cacert", str(cert), "--proxy-user", "u:pw151", f"http://127.0.0.1:{http_port}/",
        ], check=True, capture_output=True, text=True, timeout=8)
        assert ok.stdout == "nexus-h2-curl-ok", f"curl H2 unexpected: {ok.stdout!r}"
        bad = subprocess.run([
            "/usr/bin/curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--proxy-http2",
            "--proxy", f"https://127.0.0.1:{sp_port}", "--proxy-cacert", str(cert),
            "--proxy-user", "u:badpw", f"http://127.0.0.1:{http_port}/",
        ], capture_output=True, text=True, timeout=8)
        assert bad.returncode != 0 or "407" in bad.stdout or "407" in bad.stderr, "Expected 407 rejection on wrong creds"
        print("Suite 1 PASS: HTTP/2 CONNECT + curl --proxy-http2 + 407 auth")
    finally:
        stop_proc(cp); stop_proc(sp)

def suite_2_auto_h1_fallback(nexus: pathlib.Path, d: pathlib.Path, echo_port: int, http_port: int, cert: pathlib.Path, key: pathlib.Path) -> None:
    h1_port, cp_port = free_port(), free_port()
    stop_ev = threading.Event(); run_h1_py_proxy(cert, key, h1_port, stop_ev)
    cp = start_nexus(nexus, write_kdl(d / "s2c.kdl", f'''schema-version 1; role "client"
inbound "s5" type="socks5" {{ listen host="127.0.0.1" port={cp_port}; authentication "none"; }}
outbound "hc" type="http-connect" {{
    http-version "auto"; server host="127.0.0.1" port={h1_port}
    tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}
}}
outbound "direct" type="direct"; routing {{ default-outbound "hc"; }}
'''), cp_port, "s2_cli")
    try:
        payload = b"auto-alpn-http11-fallback-" * 200
        assert socks5_echo(cp_port, echo_port, payload) == payload, "Suite 2 auto->H1 fallback echo failed"
        c = subprocess.run([
            "/usr/bin/curl", "-sS", "--http1.1", "--proxy", f"https://127.0.0.1:{h1_port}",
            "--proxy-cacert", str(cert), f"http://127.0.0.1:{http_port}/",
        ], check=True, capture_output=True, text=True, timeout=8)
        assert c.stdout == "nexus-h2-curl-ok"
        print("Suite 2 PASS: auto ALPN fallback to HTTP/1.1 + curl HTTPS/1.1 proxy")
    finally:
        stop_proc(cp); stop_ev.set()

def suite_3_h3_proxy_and_connect_udp(nexus: pathlib.Path, d: pathlib.Path, echo_port: int, udp_port: int, cert: pathlib.Path, key: pathlib.Path) -> None:
    pw = write_pw(d / "h3.pw", "h3sec")
    sp_port, cp_port = free_port(udp=True), free_port()
    sp = start_nexus(nexus, write_kdl(d / "s3s.kdl", f'''schema-version 1; role "server"
inbound "h3-in" type="http" {{
    listen host="127.0.0.1" port={sp_port}; authentication "password" username="u3" password-file="{pw}"
    tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}; http2 #false; http3 #true; connect-udp #true
}}
outbound "direct" type="direct"; routing {{ default-outbound "direct"; }}
'''), None, "s3_srv")
    cp = start_nexus(nexus, write_kdl(d / "s3c.kdl", f'''schema-version 1; role "client"
inbound "s5" type="socks5" {{ listen host="127.0.0.1" port={cp_port}; authentication "none"; }}
outbound "hc" type="http-connect" {{
    http-version "h3"; server host="127.0.0.1" port={sp_port}; authentication username="u3" password-file="{pw}"; udp #true
    tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}
}}
outbound "direct" type="direct"; routing {{ default-outbound "hc"; }}
'''), cp_port, "s3_cli")
    try:
        tcp_msg = b"h3-connect-tcp-payload-" * 300
        assert socks5_echo(cp_port, echo_port, tcp_msg) == tcp_msg, "Suite 3 H3 CONNECT TCP failed"
        udp_msg = b"rfc9298-connect-udp-ping"
        assert socks5_udp_echo(cp_port, udp_port, udp_msg) == udp_msg, "Suite 3 RFC 9298 CONNECT-UDP failed"
        print("Suite 3 PASS: HTTP/3 CONNECT + RFC 9298 CONNECT-UDP")
    finally:
        stop_proc(cp); stop_proc(sp)

def naive_cli_kdl(port: int, srv_port: int, user: str, pw: pathlib.Path, cert: pathlib.Path, proto: str, pad: bool) -> str:
    return f'''schema-version 1; role "client"
inbound "s5" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "nv" type="naive" {{
    protocol "{proto}"; server host="127.0.0.1" port={srv_port}; authentication username="{user}" password-file="{pw}"
    tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}; padding {"#true" if pad else "#false"}
}}
outbound "direct" type="direct"; routing {{ default-outbound "nv"; }}
'''

def suite_4_naive_h2(nexus: pathlib.Path, d: pathlib.Path, echo_port: int, cert: pathlib.Path, key: pathlib.Path) -> None:
    pw = write_pw(d / "n2.pw", "naivepw")
    sp_port, c1_port, c2_port = free_port(), free_port(), free_port()
    sp = start_nexus(nexus, write_kdl(d / "s4s.kdl", f'''schema-version 1; role "server"
inbound "naive-in" type="naive" {{
    listen host="127.0.0.1" port={sp_port}; protocol "h2"
    tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
    authentication {{ user "alice" username="alice" password-file="{pw}"; }}; padding #true; fallback-status 404
}}
outbound "direct" type="direct"; routing {{ default-outbound "direct"; }}
'''), sp_port, "s4_srv")
    p1 = start_nexus(nexus, write_kdl(d / "s4p.kdl", naive_cli_kdl(c1_port, sp_port, "alice", pw, cert, "h2", True)), c1_port, "s4_pad")
    p2 = start_nexus(nexus, write_kdl(d / "s4n.kdl", naive_cli_kdl(c2_port, sp_port, "alice", pw, cert, "h2", False)), c2_port, "s4_nopad")
    try:
        big = os.urandom(70000)
        assert socks5_echo(c1_port, echo_port, big) == big, "Suite 4 padding ON >64KiB failed"
        assert socks5_echo(c1_port, echo_port, b"frag1byte-test", byte_by_byte=True) == b"frag1byte-test", "Suite 4 1-byte frag failed"
        assert socks5_echo(c2_port, echo_port, b"nopad-plain-stream") == b"nopad-plain-stream", "Suite 4 padding OFF failed"
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futs = [pool.submit(socks5_echo, c1_port, echo_port, f"mux-{i}".encode() * 64) for i in range(6)]
            for i, f in enumerate(futs): assert f.result() == f"mux-{i}".encode() * 64
        st1, body1 = h2_decoy_probe(sp_port, cert, [(":method", "GET"), (":path", "/"), (":scheme", "https"), (":authority", "localhost")])
        assert st1 == "404" and b"<html" in body1.lower(), f"Expected 404 HTML decoy, got {body1!r}"
        st2, body2 = h2_decoy_probe(sp_port, cert, [
            (":method", "CONNECT"), (":authority", f"127.0.0.1:{echo_port}"), ("proxy-authorization", "Basic d3Jvbmc6d3Jvbmc="),
        ])
        assert st2 == "404" and b"<html" in body2.lower(), f"Expected 404 decoy on bad auth, got {body2!r}"
        print("Suite 4 PASS: NaiveProxy H2 padding ON/OFF + 1B frag + >64KiB + mux + 404 HTML decoy")
    finally:
        stop_proc(p2); stop_proc(p1); stop_proc(sp)

def suite_5_naive_h3_and_both(nexus: pathlib.Path, d: pathlib.Path, echo_port: int, cert: pathlib.Path, key: pathlib.Path) -> None:
    pw = write_pw(d / "n3.pw", "h3pass")
    sp_port, c3_port, c2_port = free_dual_port(), free_port(), free_port()
    sp = start_nexus(nexus, write_kdl(d / "s5s.kdl", f'''schema-version 1; role "server"
inbound "naive-both" type="naive" {{
    listen host="127.0.0.1" port={sp_port}; protocol "both"
    tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
    authentication {{ user "bob" username="bob" password-file="{pw}"; }}; padding #true; fallback-status 200
}}
outbound "direct" type="direct"; routing {{ default-outbound "direct"; }}
'''), sp_port, "s5_srv")
    p3 = start_nexus(nexus, write_kdl(d / "s5h3.kdl", naive_cli_kdl(c3_port, sp_port, "bob", pw, cert, "h3", True)), c3_port, "s5_h3")
    p2 = start_nexus(nexus, write_kdl(d / "s5h2.kdl", naive_cli_kdl(c2_port, sp_port, "bob", pw, cert, "h2", True)), c2_port, "s5_h2")
    try:
        big = os.urandom(68000)
        assert socks5_echo(c3_port, echo_port, big) == big, "Suite 5 Naive H3 >64KiB failed"
        assert socks5_echo(c2_port, echo_port, b"dual-both-h2") == b"dual-both-h2", "Suite 5 Naive both-H2 failed"
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futs = [pool.submit(socks5_echo, c3_port, echo_port, f"h3mux-{i}".encode() * 50) for i in range(4)]
            for i, f in enumerate(futs): assert f.result() == f"h3mux-{i}".encode() * 50
        st, body = h2_decoy_probe(sp_port, cert, [(":method", "GET"), (":path", "/"), (":scheme", "https"), (":authority", "localhost")])
        assert st == "200" and b"<html" in body.lower(), f"Expected 200 HTML decoy, got {body!r}"
        print("Suite 5 PASS: NaiveProxy H3 + protocol=both + mux + 200 HTML decoy")
    finally:
        stop_proc(p2); stop_proc(p3); stop_proc(sp)

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--nexus", default=None)
    nexus = find_nexus_bin(ap.parse_args().nexus)
    echo, udp_echo = TcpEchoServer(), UdpEchoServer()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), HttpGetHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-b151-live-") as td:
            d = pathlib.Path(td); cert, key = make_cert(d)
            suite_1_h2_proxy(nexus, d, echo.port, httpd.server_address[1], cert, key)
            suite_2_auto_h1_fallback(nexus, d, echo.port, httpd.server_address[1], cert, key)
            suite_3_h3_proxy_and_connect_udp(nexus, d, echo.port, udp_echo.port, cert, key)
            suite_4_naive_h2(nexus, d, echo.port, cert, key)
            suite_5_naive_h3_and_both(nexus, d, echo.port, cert, key)
        print("batch151_live_integration: ALL 5 SUITES PASSED")
        return 0
    finally:
        httpd.shutdown(); httpd.server_close(); echo.close(); udp_echo.close()

if __name__ == "__main__":
    sys.exit(main())
