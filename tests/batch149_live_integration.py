#!/usr/bin/env python3
"""Batch 149 live end-to-end integration tests against the real nexus binary."""
import concurrent.futures, http.client, os, pathlib, shutil, socket, struct, subprocess, sys, tempfile, threading, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
NEXUS_BIN = pathlib.Path(os.environ.get("NEXUS_BIN", str(ROOT / "target/x86_64-linux-gnu/a5c87b0b409ddfec/bin/nexus")))


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_udp_block(count: int) -> list[int]:
    for _ in range(40):
        base, socks = free_port(socket.SOCK_DGRAM), []
        try:
            for i in range(count):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(("127.0.0.1", base + i)); socks.append(s)
            return [base + i for i in range(count)]
        except OSError: pass
        finally:
            for s in socks: s.close()
    raise RuntimeError("could not reserve contiguous UDP port block")


def write_secret(path: pathlib.Path, content: str) -> pathlib.Path:
    path.write_text(content + "\n"); os.chmod(path, 0o600); return path


def wait_tcp(port: int, proc: subprocess.Popen, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate()
            raise RuntimeError(f"nexus exited early rc={proc.returncode}\nout={out}\nerr={err}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3): return
        except OSError: time.sleep(0.04)
    raise RuntimeError(f"timed out waiting for TCP port {port}")


def start_nexus(cfg_path: pathlib.Path) -> subprocess.Popen:
    return subprocess.Popen([str(NEXUS_BIN), "run", "--config", str(cfg_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def stop_nexus(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=2)


class EchoServer:
    def __init__(self, udp: bool = False) -> None:
        self.udp = udp
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        if not udp:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        if not udp:
            self.sock.listen(32)
        self.sock.settimeout(0.2)
        self.port, self.stop_ev = self.sock.getsockname()[1], threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _handle_tcp(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(4.0)
            try:
                while data := conn.recv(4096):
                    conn.sendall(data)
            except OSError:
                pass

    def _run(self) -> None:
        while not self.stop_ev.is_set():
            try:
                if self.udp:
                    data, addr = self.sock.recvfrom(4096)
                    self.sock.sendto(b"ECHO:" + data, addr)
                else:
                    c, _ = self.sock.accept()
                    threading.Thread(target=self._handle_tcp, args=(c,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self) -> None:
        self.stop_ev.set()
        self.sock.close()


def socks5_echo(proxy_port: int, dst_port: int, payload: bytes, host: str = "127.0.0.1") -> bytes:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as s:
        s.settimeout(5.0)
        s.sendall(b"\x05\x01\x00")
        assert s.recv(2) == b"\x05\x00"
        req = (b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", dst_port)
               if host == "127.0.0.1"
               else b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + struct.pack("!H", dst_port))
        s.sendall(req)
        rep = b""
        while len(rep) < 10:
            chunk = s.recv(10 - len(rep))
            assert chunk, "unexpected EOF on SOCKS5 reply"
            rep += chunk
        assert rep[1] == 0, f"SOCKS5 connect failed: {rep!r}"
        s.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = s.recv(len(payload) - len(got))
            assert chunk, "unexpected EOF on echo"
            got += chunk
        return got


def socks4_connect(proxy_port: int, dst_ip: str, dst_port: int, domain: str | None = None, userid: bytes = b"") -> tuple[socket.socket, bytes]:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
    s.settimeout(5.0)
    pkt = (struct.pack("!BBH4s", 4, 1, dst_port, socket.inet_aton(dst_ip)) + userid + b"\x00"
           if domain is None
           else struct.pack("!BBH4s", 4, 1, dst_port, b"\x00\x00\x00\x01") + userid + b"\x00" + domain.encode() + b"\x00")
    s.sendall(pkt)
    rep = b""
    while len(rep) < 8:
        chunk = s.recv(8 - len(rep))
        if not chunk:
            break
        rep += chunk
    return s, rep


def generate_cert(tmp: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    cert, key = tmp / "server.crt", tmp / "server.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-keyout", str(key), "-out", str(cert), "-days", "2", "-nodes",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    os.chmod(key, 0o600)
    return cert, key


def test_149_1_socks4(tmp: pathlib.Path, echo_port: int) -> None:
    p_open, p_auth, p_c4, p_c4a = free_port(), free_port(), free_port(), free_port()
    pw = write_secret(tmp / "socks_pw.txt", "secret-pw")
    cfg_srv, cfg_cli = tmp / "s4_srv.kdl", tmp / "s4_cli.kdl"
    cfg_srv.write_text(f'''schema-version 1
role "client"
inbound "open" type="socks5" {{ listen host="127.0.0.1" port={p_open}; authentication "none"; }}
inbound "locked" type="socks5" {{ listen host="127.0.0.1" port={p_auth}; authentication "password" username="u1" password-file="{pw}"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    cfg_cli.write_text(f'''schema-version 1
role "client"
inbound "in4" type="socks5" {{ listen host="127.0.0.1" port={p_c4}; authentication "none"; }}
inbound "in4a" type="socks5" {{ listen host="127.0.0.1" port={p_c4a}; authentication "none"; }}
outbound "direct" type="direct"
outbound "up4" type="socks4" {{ server host="127.0.0.1" port={p_open}; userid "alice"; }}
outbound "up4a" type="socks4a" {{ server host="127.0.0.1" port={p_open}; userid "bob"; }}
routing {{
    tcp-program sniff-timeout-ms=500 unknown="skip" {{
        rule action="route" outbound="up4" {{ inbound "in4"; }}
        rule action="route" outbound="up4a" {{ inbound "in4a"; }}
    }}
    default-outbound "direct"
}}
''')
    ps, pc = start_nexus(cfg_srv), start_nexus(cfg_cli)
    try:
        for p, pr in ((p_open, ps), (p_auth, ps), (p_c4, pc), (p_c4a, pc)):
            wait_tcp(p, pr)
        s, rep = socks4_connect(p_open, "127.0.0.1", echo_port, userid=b"u")
        with s:
            assert len(rep) == 8 and rep[0] == 0 and rep[1] == 0x5A, f"SOCKS4 failed: {rep!r}"
            s.sendall(b"hello-socks4")
            assert s.recv(64) == b"hello-socks4"
        s, rep = socks4_connect(p_open, "0.0.0.1", echo_port, domain="localhost")
        with s:
            assert len(rep) == 8 and rep[0] == 0 and rep[1] == 0x5A, f"SOCKS4a failed: {rep!r}"
            s.sendall(b"hello-socks4a")
            assert s.recv(64) == b"hello-socks4a"
        s, rep = socks4_connect(p_auth, "127.0.0.1", echo_port)
        with s:
            assert len(rep) == 8 and rep[1] == 0x5B, f"auth inbound must reject SOCKS4: {rep!r}"
        assert socks5_echo(p_c4, echo_port, b"via-socks4-out") == b"via-socks4-out"
        assert socks5_echo(p_c4a, echo_port, b"via-socks4a-out", host="localhost") == b"via-socks4a-out"
    finally:
        stop_nexus(pc)
        stop_nexus(ps)
    print("  [PASS] 149.1 SOCKS4 / SOCKS4a inbound + outbound + auth rejection")


def test_149_2_fixed_udp(tmp: pathlib.Path, udp_port: int) -> None:
    p_fudp, cfg = free_port(socket.SOCK_DGRAM), tmp / "fixed_udp.kdl"
    cfg.write_text(f'''schema-version 1
role "client"
inbound "fudp" type="fixed-udp" {{ listen host="127.0.0.1" port={p_fudp}; target host="127.0.0.1" port={udp_port}; idle-timeout-ms 5000; }}
outbound "direct" type="direct"
routing {{
    tcp-program sniff-timeout-ms=500 unknown="skip" udp=#true {{
        rule action="route-options" udp-adaptive-timeout=#true {{ network "udp"; }}
        rule action="route" outbound="direct" {{ network "udp"; }}
    }}
    default-outbound "direct"
}}
''')
    proc = start_nexus(cfg)
    try:
        time.sleep(0.35)
        assert proc.poll() is None, f"fixed-udp exited: {proc.communicate()}"
        for tag in (b"client-A", b"client-B"):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
                c.settimeout(3.0)
                c.sendto(tag, ("127.0.0.1", p_fudp))
                data, _ = c.recvfrom(1024)
                assert data == b"ECHO:" + tag, f"unexpected fixed-udp reply: {data!r}"
    finally:
        stop_nexus(proc)
    print("  [PASS] 149.2 fixed-udp inbound direct multi-client forwarding")


def test_149_3_trojan_anytls_transports(tmp: pathlib.Path, cert: pathlib.Path, key: pathlib.Path, echo_port: int) -> None:
    pw = write_secret(tmp / "ta_pw.txt", "super-secret-149")
    transports = [
        ("ws", 'transport "websocket" { path "/ws"; host "localhost"; }'),
        ("hu", 'transport "httpupgrade" { path "/hu"; host "localhost"; }'),
        ("grpc", 'transport "grpc" { service-name "tun"; authority "localhost"; }'),
    ]
    for proto in ("trojan", "anytls"):
        for tname, tblock in transports:
            p_srv, p_cli = free_port(), free_port()
            srv_kdl, cli_kdl = tmp / f"{proto}_{tname}_srv.kdl", tmp / f"{proto}_{tname}_cli.kdl"
            srv_kdl.write_text(f'''schema-version 1
role "server"
inbound "in" type="{proto}" {{
    listen host="127.0.0.1" port={p_srv}
    authentication {{ user "u1" password-file="{pw}"; }}
    tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
    {tblock}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
            cli_kdl.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={p_cli}; authentication "none"; }}
outbound "direct" type="direct"
outbound "up" type="{proto}" {{
    server host="127.0.0.1" port={p_srv}
    authentication {{ password-file "{pw}"; }}
    tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}
    {tblock}
}}
routing {{ default-outbound "up"; }}
''')
            ps, pc = start_nexus(srv_kdl), start_nexus(cli_kdl)
            try:
                wait_tcp(p_srv, ps)
                wait_tcp(p_cli, pc)
                msg = f"hello-{proto}-{tname}".encode()
                assert socks5_echo(p_cli, echo_port, msg) == msg, f"{proto}/{tname} echo mismatch"
                if tname == "grpc":
                    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                        futs = [ex.submit(socks5_echo, p_cli, echo_port, f"mux-{proto}-{i}".encode()) for i in range(4)]
                        for i, fut in enumerate(futs):
                            assert fut.result() == f"mux-{proto}-{i}".encode(), f"{proto}/grpc concurrent {i}"
                    reuse = f"reuse-{proto}-after-mux".encode()
                    assert socks5_echo(p_cli, echo_port, reuse) == reuse, f"{proto}/grpc reuse mismatch"
            finally:
                stop_nexus(pc)
                stop_nexus(ps)
                assert pc.returncode in (0, -15), f"{proto}/{tname} client unclean exit: {pc.returncode}"
                assert ps.returncode in (0, -15), f"{proto}/{tname} server unclean exit: {ps.returncode}"
    print("  [PASS] 149.3 Trojan & AnyTLS over WebSocket / HTTPUpgrade / gRPC (6/6 live pairs)")


def test_149_4_snell_v5(tmp: pathlib.Path, echo_port: int) -> None:
    p_srv, p_cli = free_port(), free_port()
    psk = write_secret(tmp / "snell.psk", "0123456789abcdef0123456789abcdef")
    srv_kdl, cli_kdl = tmp / "snell_srv.kdl", tmp / "snell_cli.kdl"
    srv_kdl.write_text(f'''schema-version 1
role "server"
inbound "sn" type="snell" {{ listen host="127.0.0.1" port={p_srv}; version 5; psk-file "{psk}"; replay-window-seconds 60; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    cli_kdl.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={p_cli}; authentication "none"; }}
outbound "direct" type="direct"
outbound "up" type="snell" {{ server host="127.0.0.1" port={p_srv}; version 5; psk-file "{psk}"; }}
routing {{ default-outbound "up"; }}
''')
    ps, pc = start_nexus(srv_kdl), start_nexus(cli_kdl)
    try:
        wait_tcp(p_srv, ps)
        wait_tcp(p_cli, pc)
        assert socks5_echo(p_cli, echo_port, b"snell-v5-roundtrip") == b"snell-v5-roundtrip"
    finally:
        stop_nexus(pc)
        stop_nexus(ps)
    print("  [PASS] 149.4 Snell v5 outbound <-> Nexus Snell v5 inbound")


def test_149_5_hy2_port_hopping(tmp: pathlib.Path, cert: pathlib.Path, key: pathlib.Path, echo_port: int) -> None:
    p_hy2_srv, hop_ports, p_cli = free_port(socket.SOCK_DGRAM), free_udp_block(4), free_port()
    pw = write_secret(tmp / "hy2_pw.txt", "hy2-hop-secret")
    stop_ev, touched_ports, lock = threading.Event(), set(), threading.Lock()
    hop_socks = []
    for hp in hop_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", hp))
        s.settimeout(0.1)
        hop_socks.append((hp, s))
    up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up_sock.bind(("127.0.0.1", 0))
    up_sock.settimeout(0.1)
    state = {"client": None, "last_sock": hop_socks[0][1]}

    def fwd_in(hp: int, sock: socket.socket) -> None:
        while not stop_ev.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                with lock:
                    touched_ports.add(hp)
                    state["client"], state["last_sock"] = addr, sock
                up_sock.sendto(data, ("127.0.0.1", p_hy2_srv))
            except OSError:
                continue

    def fwd_out() -> None:
        while not stop_ev.is_set():
            try:
                data, _ = up_sock.recvfrom(65535)
                with lock:
                    cli_addr, out_s = state["client"], state["last_sock"]
                if cli_addr:
                    out_s.sendto(data, cli_addr)
            except OSError:
                continue

    for hp, s in hop_socks:
        threading.Thread(target=fwd_in, args=(hp, s), daemon=True).start()
    threading.Thread(target=fwd_out, daemon=True).start()
    srv_kdl, cli_kdl = tmp / "hy2_srv.kdl", tmp / "hy2_cli.kdl"
    srv_kdl.write_text(f'''schema-version 1
role "server"
inbound "hy" type="hysteria2" {{
    listen host="127.0.0.1" port={p_hy2_srv}
    authentication {{ user "u1" password-file="{pw}"; }}
    tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    cli_kdl.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={p_cli}; authentication "none"; }}
outbound "direct" type="direct"
outbound "up" type="hysteria2" {{
    server host="127.0.0.1" port={hop_ports[0]}
    authentication {{ password-file "{pw}"; }}
    tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}
    quic {{ ports "{hop_ports[0]}-{hop_ports[-1]}"; hop-interval-ms 600; }}
}}
routing {{ default-outbound "up"; }}
''')
    ps, pc = start_nexus(srv_kdl), start_nexus(cli_kdl)
    try:
        time.sleep(0.35)
        wait_tcp(p_cli, pc)
        with socket.create_connection(("127.0.0.1", p_cli), timeout=5.0) as s:
            s.settimeout(5.0)
            s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
            s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", echo_port))
            rep = s.recv(10); assert len(rep) == 10 and rep[1] == 0
            for i in range(4):
                msg = f"hop-ping-{i}".encode()
                s.sendall(msg); assert s.recv(64) == msg; time.sleep(0.55)
        assert len(touched_ports) >= 2, f"expected >=2 hopped ports, saw {touched_ports}"
    finally:
        stop_nexus(pc); stop_nexus(ps); stop_ev.set()
        for _, s in hop_socks: s.close()
        up_sock.close()
    print(f"  [PASS] 149.5 Hysteria 2 periodic random port hopping (observed {len(touched_ports)} distinct ports: {sorted(touched_ports)})")


def raw_http(port: int, method: str, target: str, token: str | None = None) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4.0)
    conn.request(method, target, headers={"Authorization": f"Bearer {token}"} if token else {})
    resp = conn.getresponse(); body, headers = resp.read(), {k.lower(): v for k, v in resp.getheaders()}; conn.close()
    return resp.status, headers, body


def test_149_6_dashboard_root(tmp: pathlib.Path) -> None:
    web_dist = ROOT / "web/dist"; assert (web_dist / "index.html").is_file(), "web/dist/index.html missing"
    dash = tmp / "dash"; shutil.copytree(web_dist, dash)
    (dash / "escape.html").symlink_to("/etc/passwd")
    (dash / ".env").write_text("SECRET=1\n"); (dash / "secret.kdl").write_text("schema-version 1\n")
    p_socks, p_http, tok = free_port(), free_port(), "dashboard-bearer-secret-token-149"
    tok_file, cfg = write_secret(tmp / "tok.txt", tok), tmp / "dash.kdl"
    cfg.write_text(f'''schema-version 1
role "client"
control http-listen="127.0.0.1:{p_http}" bearer-token-file="{tok_file}" dashboard-root="{dash}" metrics=#true
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={p_socks}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    proc = start_nexus(cfg)
    try:
        wait_tcp(p_http, proc)
        code, hdrs, body = raw_http(p_http, "GET", "/")
        assert code == 200 and b"<nexus-app>" in body and hdrs.get("x-content-type-options") == "nosniff" and "content-security-policy" in hdrs
        code, _, body_spa = raw_http(p_http, "GET", "/connections"); assert code == 200 and body_spa == body
        js_files = list((dash / "assets").glob("*.js")); assert js_files
        code, hdrs, js_body = raw_http(p_http, "GET", f"/assets/{js_files[0].name}")
        assert code == 200 and "javascript" in hdrs.get("content-type", "") and "immutable" in hdrs.get("cache-control", "") and len(js_body) > 1000
        for bad_path, allowed in [("/../etc/passwd", {400, 403}), ("/%2e%2e/etc/passwd", {400, 403}),
                                  ("/escape.html", {403}), ("/.env", {400, 403}), ("/secret.kdl", {403}), ("/missing.js", {404})]:
            c, _, _ = raw_http(p_http, "GET", bad_path); assert c in allowed, f"{bad_path} -> {c}"
        assert raw_http(p_http, "PUT", "/index.html")[0] == 405
        assert raw_http(p_http, "GET", "/v1/status")[0] == 401
        c, _, st = raw_http(p_http, "GET", "/v1/status", token=tok); assert c == 200 and b'"state":"running"' in st
    finally:
        stop_nexus(proc)
    print("  [PASS] 149.6 control-http dashboard-root serving Vite/Lit web/dist + security sandbox")


def test_149_7_rule_explain(tmp: pathlib.Path) -> None:
    cfg = tmp / "explain.kdl"
    cfg.write_text('''schema-version 1
role "client"
dns {
    server "dns-local" type="udp" host="127.0.0.1" port=5353
    server "dns-remote" type="udp" host="127.0.0.1" port=5354
    rule domain-suffix="example.com" server="dns-remote"
    final "dns-local"
}
inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }
outbound "direct" type="direct"
outbound "proxy" type="socks5" { server host="127.0.0.1" port=1081; }
routing {
    tcp-program sniff-timeout-ms=500 unknown="skip" udp=#true {
        rule action="route-options" udp-adaptive-timeout=#true { network "udp"; }
        rule action="route" outbound="proxy" { domain-suffix "example.com"; }
    }
    default-outbound "direct"
}
''')
    def run_ex(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(NEXUS_BIN), "rule", "explain", str(cfg), "local", *args, "--oneline"], capture_output=True, text=True)

    r1 = run_ex("tcp", "app.example.com:443", "dns-qtype=HTTPS", "resolved-ip=93.184.216.34",
                "--expect-dns=dns-remote", "--expect-action=route", "--expect-outbound=proxy")
    assert r1.returncode == 0 and "dns=dns-remote" in r1.stdout and "outbound=proxy" in r1.stdout, f"{r1.stdout} {r1.stderr}"
    assert run_ex("tcp", "app.example.com:443", "resolved-ip=93.184.216.34", "--expect-outbound=direct").returncode == 1
    r3 = run_ex("udp", "1.1.1.1:53", "--expect-outbound=direct")
    assert r3.returncode == 0 and "udp-timeout-ms=10000" in r3.stdout, f"expected 10000ms: {r3.stdout}"
    r4 = run_ex("udp", "1.1.1.1:443", "--expect-outbound=direct")
    assert r4.returncode == 0 and "udp-timeout-ms=30000" in r4.stdout, f"expected 30000ms: {r4.stdout}"
    print("  [PASS] 149.7 nexus rule explain --oneline DNS+route+adaptive UDP timeout assertions")


def main() -> None:
    if not NEXUS_BIN.is_file():
        sys.exit(f"missing nexus binary: {NEXUS_BIN}")
    tcp_echo, udp_echo = EchoServer(False), EchoServer(True)
    with tempfile.TemporaryDirectory(prefix="nexus-batch149-") as td:
        tmp = pathlib.Path(td); cert, key = generate_cert(tmp)
        try:
            test_149_1_socks4(tmp, tcp_echo.port)
            test_149_2_fixed_udp(tmp, udp_echo.port)
            test_149_3_trojan_anytls_transports(tmp, cert, key, tcp_echo.port)
            test_149_4_snell_v5(tmp, tcp_echo.port)
            test_149_5_hy2_port_hopping(tmp, cert, key, tcp_echo.port)
            test_149_6_dashboard_root(tmp)
            test_149_7_rule_explain(tmp)
        finally:
            tcp_echo.close(); udp_echo.close()
    print("BATCH149_LIVE_INTEGRATION_OK")


if __name__ == "__main__":
    main()
