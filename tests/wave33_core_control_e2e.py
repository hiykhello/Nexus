#!/usr/bin/env python3
"""Wave 33 Real-Core E2E verification against the live built `nexus` binary."""
from __future__ import annotations

import base64
import gzip
import hashlib
import http.client
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
TOKEN = "wave33-e2e-secret-token-2026"


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def find_nexus_bin() -> Path:
    if len(sys.argv) > 1 and Path(sys.argv[1]).is_file():
        return Path(sys.argv[1])
    if (env := os.environ.get("NEXUS_BIN")) and Path(env).is_file():
        return Path(env)
    root = Path(__file__).resolve().parent.parent
    bins = sorted(
        (
            p for base in (root / "target", root / ".mcpp" / "build")
            if base.is_dir()
            for p in base.rglob("nexus")
            if p.is_file() and os.access(p, os.X_OK)
        ),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not bins:
        raise RuntimeError("cannot locate built nexus binary; pass path as argv[1] or NEXUS_BIN")
    return bins[0]


class MockDnsServer:
    def __init__(self, answers: dict[str, str]):
        self.answers = answers
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(4096)
            except (TimeoutError, OSError):
                continue
            if len(data) < 17:
                continue
            pos, labels = 12, []
            while pos < len(data) and data[pos] != 0:
                n = data[pos]
                labels.append(data[pos + 1 : pos + 1 + n].decode("ascii", errors="ignore"))
                pos += 1 + n
            qend = pos + 1
            qname = ".".join(labels).lower()
            qtype, qclass = struct.unpack("!HH", data[qend : qend + 4])
            question = data[12 : qend + 4]
            if qtype == 1:
                ip = self.answers.get(qname, "198.51.100.77")
                hdr = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, qclass, 60, 4) + socket.inet_aton(ip)
                self.sock.sendto(hdr + question + rr, peer)
            else:
                hdr = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0)
                self.sock.sendto(hdr + question, peer)


class ProbeHttpServer:
    def __init__(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self) -> None:
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:
                body = b"wave33-ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=2)


def http_req(
    port: int, method: str, path: str, headers: dict[str, str] | None = None, body: bytes | None = None, timeout: float = 5.0
) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
    finally:
        conn.close()


class UdpEchoServer:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(4096)
                self.sock.sendto(data, peer)
            except (TimeoutError, OSError):
                continue


def socks5_udp_echo(socks_port: int, target_ip: str, target_port: int, payload: bytes) -> bytes | None:
    with socket.create_connection(("127.0.0.1", socks_port), timeout=3.0) as tcp:
        tcp.settimeout(3.0)
        tcp.sendall(b"\x05\x01\x00")
        if tcp.recv(2) != b"\x05\x00":
            return None
        tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        rep = tcp.recv(10)
        if len(rep) < 10 or rep[1] != 0 or rep[3] != 1:
            return None
        relay_addr = (socket.inet_ntoa(rep[4:8]), struct.unpack("!H", rep[8:10])[0])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(3.0)
            hdr = b"\x00\x00\x00\x01" + socket.inet_aton(target_ip) + struct.pack("!H", target_port)
            udp.sendto(hdr + payload, relay_addr)
            try:
                resp, _ = udp.recvfrom(4096)
            except (TimeoutError, OSError):
                return None
            return resp[10:] if len(resp) >= 10 else None


def socks5_http_get(socks_port: int, target_ip: str, target_port: int) -> bytes | None:
    with socket.create_connection(("127.0.0.1", socks_port), timeout=3.0) as s:
        s.settimeout(3.0)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return None
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(target_ip) + struct.pack("!H", target_port))
        rep = s.recv(10)
        if len(rep) < 4 or rep[1] != 0:
            return None
        s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        chunks = []
        while chunk := s.recv(4096):
            chunks.append(chunk)
        return b"".join(chunks)


def ws_frame(opcode: int, payload: bytes) -> bytes:
    mask = b"\x37\xfa\x21\x3d"
    hdr = bytearray([0x80 | (opcode & 0x0F)])
    n = len(payload)
    if n < 126:
        hdr.append(0x80 | n)
    elif n <= 65535:
        hdr.append(0x80 | 126)
        hdr.extend(struct.pack("!H", n))
    else:
        hdr.append(0x80 | 127)
        hdr.extend(struct.pack("!Q", n))
    hdr.extend(mask)
    return bytes(hdr) + bytes(b ^ mask[i & 3] for i, b in enumerate(payload))


def ws_recv(sock: socket.socket, buf: bytearray) -> tuple[int, bytes]:
    def need(n: int) -> None:
        while len(buf) < n:
            chunk = sock.recv(4096)
            if not chunk:
                raise EOFError("ws closed")
            buf.extend(chunk)

    need(2)
    op, length, pos = buf[0] & 0x0F, buf[1] & 0x7F, 2
    if length == 126:
        need(4)
        length, pos = struct.unpack("!H", buf[2:4])[0], 4
    elif length == 127:
        need(10)
        length, pos = struct.unpack("!Q", buf[2:10])[0], 10
    need(pos + length)
    payload = bytes(buf[pos : pos + length])
    del buf[: pos + length]
    return op, payload


def ws_connect(port: int, path: str, extra: dict[str, str] | None = None) -> tuple[int, socket.socket, bytearray]:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")
    s = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    s.settimeout(5.0)
    hdrs = [
        f"GET {path} HTTP/1.1", f"Host: 127.0.0.1:{port}",
        "Upgrade: websocket", "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13",
        *(f"{k}: {v}" for k, v in (extra or {}).items()),
    ]
    s.sendall(("\r\n".join(hdrs) + "\r\n\r\n").encode("ascii"))
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
    end = buf.find(b"\r\n\r\n")
    lines = bytes(buf[:end]).decode("iso-8859-1").split("\r\n")
    del buf[: end + 4]
    status = int(lines[0].split()[1])
    parsed = {k.lower().strip(): v.strip() for ln in lines[1:] if ":" in ln for k, v in [ln.split(":", 1)]}
    if status == 101:
        assert parsed.get("sec-websocket-accept") == expected, (parsed, expected)
    return status, s, buf


def start_nexus(nexus_bin: Path, cfg: Path, http_port: int, auth: dict[str, str]) -> subprocess.Popen[str]:
    proc = subprocess.Popen([str(nexus_bin), "run", "--config", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate(timeout=2)
            raise RuntimeError(f"nexus exited ({proc.returncode}): stdout={out}\nstderr={err}")
        try:
            if http_req(http_port, "GET", "/v1/status", headers=auth, timeout=0.5)[0] == 200:
                return proc
        except OSError:
            pass
        time.sleep(0.1)
    proc.terminate()
    out, err = proc.communicate(timeout=3)
    raise RuntimeError(f"nexus not ready on :{http_port}: stdout={out}\nstderr={err}")


def stop_nexus(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


def main() -> None:
    nexus_bin = find_nexus_bin()
    print(f"Using nexus binary: {nexus_bin}")
    auth = {"Authorization": f"Bearer {TOKEN}"}

    with tempfile.TemporaryDirectory(prefix="nexus_w33_e2e_") as tmp:
        root = Path(tmp)
        state_dir, cache_dir = root / "state", root / "cache"
        state_dir.mkdir(mode=0o700)
        cache_dir.mkdir(mode=0o700)
        token_file = root / "control.token"
        token_file.write_text(TOKEN + "\n")
        token_file.chmod(0o600)
        local_rule = root / "local-rules.kdl"
        local_rule.write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.1/32"\n')

        dns_mock = MockDnsServer({"logical.test": "198.51.100.42"})
        dns_mock.start()
        probe_srv = ProbeHttpServer()
        probe_srv.start()
        udp_echo = UdpEchoServer()
        udp_echo.start()
        socks_port, http_port, dns_port = free_port(), free_port(), free_port(socket.SOCK_DGRAM)

        cfg = root / "config.kdl"
        cfg.write_text(f'''schema-version 1
role "client"
workers 1
state {{ directory "{state_dir}"; cache-directory "{cache_dir}"; }}
log {{ level "info"; format "jsonl"; }}
control http-listen="127.0.0.1:{http_port}" bearer-token-file="{token_file}"
inbounds {{ socks5 "socks-in" {{ listen "127.0.0.1:{socks_port}"; authentication "none"; }}; }}
outbounds {{ direct; block; }}
dns {{
    listen host="127.0.0.1" port={dns_port}
    servers {{
        udp "upstream" host="127.0.0.1" port={dns_mock.port}
        udp "fakeip-srv" host="127.0.0.1" port={dns_mock.port}
    }}
    fake-ip server="fakeip-srv" ipv4-pool="198.18.0.0/22" ttl-seconds=60
    rules {{
        - mode="logical" logic="and" to="upstream" {{ domain-suffix "logical.test"; query-type "A"; }}
        - domain-suffix "fake.test" to="fakeip-srv"
    }}
    final "upstream"
}}
routing {{
    rule-set "local-block" path="{local_rule}" format="kdl"
    rules udp=#true {{
        - network "icmp" action="bypass"
        - port {udp_echo.port} action="bypass"
        - ip-cidr "10.0.0.0/8" action="bypass"
        - rule-set "local-block" to="block"
        - default "direct"
    }}
}}
''')

        proc = start_nexus(nexus_bin, cfg, http_port, auth)
        try:
            # 1. Embedded Web Dashboard
            st, hdrs, html = http_req(http_port, "GET", "/")
            assert st == 200 and "text/html" in hdrs.get("content-type", ""), (st, hdrs)
            m = re.search(rb'src="(/assets/[^"]+\.js)"', html)
            assert m, html[:200]
            js_path = m.group(1).decode("ascii")
            st, hdrs, gz_js = http_req(http_port, "GET", js_path, {"Accept-Encoding": "gzip"})
            assert st == 200 and hdrs.get("content-encoding") == "gzip" and len(gzip.decompress(gz_js)) > 1000
            st, hdrs, _ = http_req(http_port, "GET", js_path, {"Accept-Encoding": "identity"})
            assert st == 406 and "accept-encoding" in hdrs.get("vary", "").lower(), (st, hdrs)
            print("  [PASS] embedded Web Dashboard (GET /, gzipped JS, 406 identity)")

            # 2. Control REST API
            assert http_req(http_port, "GET", "/v1/status")[0] == 401
            st, _, body = http_req(http_port, "GET", "/v1/status", auth)
            assert st == 200 and json.loads(body).get("state") == "running", (st, body)
            st, _, body = http_req(http_port, "GET", "/v1/mode", auth)
            assert st == 200 and json.loads(body).get("mode") == "rule", (st, body)
            st, _, body = http_req(http_port, "GET", "/v1/rules", auth)
            assert st == 200 and any(r["action"] == "bypass" for r in json.loads(body)["rules"])
            st, _, body = http_req(http_port, "GET", "/v1/dns/query?name=logical.test&type=A", auth)
            assert st == 200 and "198.51.100.42" in body.decode("utf-8", errors="ignore"), (st, body)
            st, _, body = http_req(http_port, "GET", "/v1/dns/query?name=fake.test&type=A", auth)
            assert st == 200 and "198.18." in body.decode("utf-8", errors="ignore"), (st, body)
            st, _, body = http_req(http_port, "POST", "/v1/cache/fakeip/flush", auth)
            assert st == 200 and json.loads(body).get("fakeip") is True and json.loads(body).get("flushed", 0) >= 1, (st, body)
            st, _, body = http_req(http_port, "POST", "/v1/log-level", {**auth, "Content-Type": "application/json"}, b'{"level":"debug"}')
            assert st == 200, (st, body)
            pbody = json.dumps({"url": f"http://127.0.0.1:{probe_srv.port}/health", "timeout_ms": 2000}).encode()
            st, _, body = http_req(http_port, "POST", "/v1/outbounds/direct/probe", {**auth, "Content-Type": "application/json"}, pbody)
            assert st == 200 and ("latency_ms" in json.loads(body) or json.loads(body).get("ok") is True), (st, body)
            print("  [PASS] Control REST API (/v1/status, /v1/rules, /v1/dns/query, fakeip/flush, log-level, probe)")

            # 3. SSE live stream
            with socket.create_connection(("127.0.0.1", http_port), timeout=5.0) as sse:
                sse.settimeout(3.0)
                sse.sendall(f"GET /v1/logs?stream=1&since=0 HTTP/1.1\r\nHost: 127.0.0.1:{http_port}\r\nAuthorization: Bearer {TOKEN}\r\n\r\n".encode())
                buf = b""
                end = time.monotonic() + 3.0
                while time.monotonic() < end and b"data:" not in buf:
                    chunk = sse.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                assert b"200 OK" in buf and b"text/event-stream" in buf.lower() and b"data:" in buf, buf[:300]
            print("  [PASS] SSE live streaming (/v1/logs?stream=1)")

            # 4. RFC 6455 Multiplexed WebSocket (/v1/ws)
            st, s_bad, _ = ws_connect(http_port, f"/v1/ws?token={TOKEN}")
            s_bad.close()
            assert st == 400, st
            st, s_ori, _ = ws_connect(http_port, "/v1/ws", {"Origin": "https://evil.example"})
            s_ori.close()
            assert st == 403, st

            st, ws_b, buf_b = ws_connect(http_port, "/v1/ws", auth)
            assert st == 101, st
            ws_b.sendall(ws_frame(1, json.dumps({"type": "subscribe", "channels": ["logs", "connections", "metrics"], "since": 0, "interval_ms": 200}).encode()))
            seen: set[str] = set()
            end = time.monotonic() + 3.0
            while time.monotonic() < end and not {"subscribed", "metrics", "connections", "log"}.issubset(seen):
                op, pl = ws_recv(ws_b, buf_b)
                if op == 1:
                    seen.add(json.loads(pl.decode())["type"])
            ws_b.sendall(ws_frame(8, struct.pack("!H", 1000)))
            ws_b.close()
            assert {"subscribed", "metrics", "connections", "log"}.issubset(seen), seen

            st, ws_f, buf_f = ws_connect(http_port, "/v1/ws")
            assert st == 101, st
            ws_f.sendall(ws_frame(1, b'{"type":"auth","token":"wrong"}'))
            op, pl = ws_recv(ws_f, buf_f)
            ws_f.close()
            assert op == 8 and len(pl) >= 2 and struct.unpack("!H", pl[:2])[0] == 4401, (op, pl)

            st, ws_ok, buf_ok = ws_connect(http_port, "/v1/ws")
            assert st == 101, st
            ws_ok.sendall(ws_frame(1, json.dumps({"type": "auth", "token": TOKEN}).encode()))
            op, pl = ws_recv(ws_ok, buf_ok)
            assert op == 1 and json.loads(pl.decode()) == {"type": "auth_ok"}
            ws_ok.sendall(ws_frame(1, b'{"type":"subscribe","channels":["metrics"],"interval_ms":200}'))
            assert any(ws_recv(ws_ok, buf_ok)[1].startswith(b'{"type":"metrics"') for _ in range(4))
            ws_ok.close()
            print("  [PASS] RFC 6455 WebSocket (/v1/ws: ?token= 400, Origin 403, Bearer + first-frame auth + pub/sub)")

            # 5. SOCKS5 UDP action="bypass" + Local rule-set auto hot-reload (NO restart / NO SIGHUP)
            assert socks5_udp_echo(socks_port, "127.0.0.1", udp_echo.port, b"w33-udp-bypass") == b"w33-udp-bypass"
            assert socks5_http_get(socks_port, "127.0.0.1", probe_srv.port) is None
            gen_before = int(json.loads(http_req(http_port, "GET", "/v1/status", auth)[2])["control_generation"])
            tmp_rule = root / "local-rules.kdl.next"
            tmp_rule.write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="203.0.113.99/32"\n')
            os.replace(tmp_rule, local_rule)
            reloaded = False
            end = time.monotonic() + 5.0
            while time.monotonic() < end:
                st, _, body = http_req(http_port, "GET", "/v1/status", auth)
                if st == 200 and int(json.loads(body)["control_generation"]) > gen_before:
                    reloaded = True
                    break
                time.sleep(0.1)
            assert reloaded, "local rule-set edit did not trigger automatic hot-reload"
            resp = socks5_http_get(socks_port, "127.0.0.1", probe_srv.port)
            assert resp and b"wave33-ok" in resp, resp
            print("  [PASS] local rule-set auto hot-reload (atomic replace -> automatic route swap)")

            # 6. route-mode persistence across Core stop + restart
            st, _, body = http_req(http_port, "PUT", "/v1/mode", {**auth, "Content-Type": "application/json"}, b'{"mode":"direct"}')
            assert st == 200 and json.loads(body).get("mode") == "direct" and (state_dir / "route-mode.state").is_file(), (st, body)
            stop_nexus(proc)
            proc = start_nexus(nexus_bin, cfg, http_port, auth)
            m1 = json.loads(http_req(http_port, "GET", "/v1/mode", auth)[2])
            assert m1.get("mode") == "direct", m1

            st, _, body = http_req(http_port, "PUT", "/v1/mode", {**auth, "Content-Type": "application/json"}, b'{"mode":"global","outbound":"direct"}')
            assert st == 200 and json.loads(body).get("mode") == "global", (st, body)
            stop_nexus(proc)
            proc = start_nexus(nexus_bin, cfg, http_port, auth)
            m2 = json.loads(http_req(http_port, "GET", "/v1/mode", auth)[2])
            assert m2.get("mode") == "global" and m2.get("outbound") == "direct", m2
            print("  [PASS] route-mode restart persistence (direct & global restored via NXST01)")
        finally:
            stop_nexus(proc)
            dns_mock.stop()
            probe_srv.stop()
            udp_echo.stop()
    print("ALL WAVE 33 REAL-CORE E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
