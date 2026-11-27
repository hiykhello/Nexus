#!/usr/bin/env python3
"""Wave 25 Track B: Control API SSE streaming (/v1/status, /v1/connections, /v1/logs) + ad-hoc outbound probe."""
import argparse
import http.client
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def find_default_binary() -> Path:
    env_bin = os.environ.get("NEXUS_BIN")
    if env_bin:
        return Path(env_bin).resolve(strict=True)
    root = Path(__file__).resolve().parent.parent
    cands = sorted((root / "target").glob("**/bin/nexus"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not cands:
        raise FileNotFoundError("nexus binary not found under target/; pass binary path explicitly")
    return cands[0]


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"expected {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)


def socks5_connect(proxy_port: int, dst_ip: str, dst_port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
    s.settimeout(5.0)
    s.sendall(b"\x05\x01\x00")
    assert recv_exact(s, 2) == b"\x05\x00", "SOCKS5 greeting failed"
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(dst_ip) + struct.pack("!H", dst_port))
    rep = recv_exact(s, 10)
    assert rep[0] == 5 and rep[1] == 0, f"SOCKS5 connect failed: {rep!r}"
    return s


def http_req(port: int, method: str, path: str, token: str | None = None, body: str | None = None) -> tuple[int, dict, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10.0)
    hdrs: dict[str, str] = {}
    if token is not None:
        hdrs["Authorization"] = f"Bearer {token}"
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=body.encode("utf-8") if body is not None else None, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="replace")
        return resp.status, dict(resp.getheaders()), raw
    finally:
        conn.close()


def start_tcp_server(handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                threading.Thread(target=handler, args=(c,), daemon=True).start()
            except TimeoutError:
                continue
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1], stop


def handle_tcp_echo(c: socket.socket):
    try:
        c.settimeout(10.0)
        while data := c.recv(32768):
            c.sendall(data)
    except OSError:
        pass
    finally:
        c.close()


def handle_probe_http(c: socket.socket):
    try:
        c.settimeout(3.0)
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 4096:
            chunk = c.recv(1024)
            if not chunk: break
            raw += chunk
        first = raw.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        if "/status500" in first:
            c.sendall(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        else:
            c.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except OSError:
        pass
    finally:
        c.close()


def handle_http_connect(c: socket.socket):
    def pipe(src: socket.socket, dst: socket.socket):
        try:
            while data := src.recv(16384):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try: dst.shutdown(socket.SHUT_WR)
            except OSError: pass

    up = None
    try:
        c.settimeout(5.0)
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 4096:
            chunk = c.recv(1024)
            if not chunk: return
            raw += chunk
        parts = raw.split(b"\r\n", 1)[0].decode("ascii", errors="replace").split()
        if len(parts) < 2 or parts[0] != "CONNECT":
            c.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            return
        host, port_s = parts[1].rsplit(":", 1)
        up = socket.create_connection((host.strip("[]"), int(port_s)), timeout=3.0)
        up.settimeout(5.0)
        c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        if extra := raw.split(b"\r\n\r\n", 1)[1]:
            up.sendall(extra)
        t1 = threading.Thread(target=pipe, args=(c, up), daemon=True)
        t2 = threading.Thread(target=pipe, args=(up, c), daemon=True)
        t1.start(); t2.start(); t1.join(5.0); t2.join(5.0)
    except OSError:
        pass
    finally:
        c.close()
        if up: up.close()


class SseReader:
    def __init__(self, port: int, path: str, token: str):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        self.sock.settimeout(3.0)
        req = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\n\r\n"
        self.sock.sendall(req.encode("ascii"))
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            assert chunk, "SSE socket closed before headers"
            self.buf += chunk
        hdr, rest = self.buf.split(b"\r\n\r\n", 1)
        self.headers = hdr.decode("utf-8", errors="replace")
        self.buf = rest

    def next_event(self, timeout_s: float = 3.0) -> tuple[str, str]:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            while b"\n\n" in self.buf:
                block, self.buf = self.buf.split(b"\n\n", 1)
                text = block.decode("utf-8", errors="replace")
                if not text or text.startswith(":"):
                    continue
                ev, data_lines = "", []
                for line in text.split("\n"):
                    if line.startswith("event: "):
                        ev = line[7:]
                    elif line.startswith("data: "):
                        data_lines.append(line[6:])
                if ev or data_lines:
                    assert len(data_lines) == 1, f"expected single-line SSE data, got {data_lines!r}"
                    return ev, data_lines[0]
            self.sock.settimeout(max(0.05, deadline - time.monotonic()))
            chunk = self.sock.recv(8192)
            assert chunk, "SSE stream closed unexpectedly"
            self.buf += chunk
        raise TimeoutError("timed out waiting for SSE event")

    def close(self):
        self.sock.close()


def unix_control_cmd(sock_path: Path, line: str) -> str:
    tokens = line.split()
    wire = ("NEXUS/1 " + "\0".join(tokens)).encode("utf-8")
    sock_type = getattr(socket, "SOCK_SEQPACKET", socket.SOCK_STREAM) if sys.platform.startswith("linux") else socket.SOCK_STREAM
    with socket.socket(socket.AF_UNIX, sock_type) as s:
        s.settimeout(5.0)
        s.connect(str(sock_path))
        s.sendall(wire)
        if sock_type == socket.SOCK_STREAM:
            s.shutdown(socket.SHUT_WR)
            out = bytearray()
            while chunk := s.recv(4096):
                out.extend(chunk)
            reply = out.decode("utf-8", errors="replace")
        else:
            reply = s.recv(65536).decode("utf-8", errors="replace")
        assert reply.startswith("NEXUS/1 OK\n"), reply
        return reply[len("NEXUS/1 OK\n"):]


def run_tests(binary: Path) -> None:
    echo_srv, echo_port, echo_stop = start_tcp_server(handle_tcp_echo)
    probe_srv, probe_port, probe_stop = start_tcp_server(handle_probe_http)
    proxy_srv, proxy_port, proxy_stop = start_tcp_server(handle_http_connect)
    dead_port = reserve_port()
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-w25-ctrl-") as tmpdir:
            root = Path(tmpdir)
            front_port, ctrl_port = reserve_port(), reserve_port()
            while ctrl_port == front_port:
                ctrl_port = reserve_port()
            token = secrets.token_hex(24)
            token_file = root / "token"
            token_file.write_text(token + "\n", encoding="utf-8")
            os.chmod(token_file, 0o600)
            ctrl_sock = root / "control.sock"
            cfg = root / "config.kdl"
            # Intentionally NO url-test or fallback groups: proves ad-hoc probe works standalone!
            cfg.write_text(f'''schema-version 1
role "client"
workers 2
shutdown-grace-ms 400
log {{ level "info"; ring-level "info"; ring-capacity 256; }}
control socket="{ctrl_sock}" http-listen="127.0.0.1:{ctrl_port}" bearer-token-file="{token_file}" metrics=#true
inbound "mixed" type="mixed" {{
    listen host="127.0.0.1" port={front_port}
    authentication "none"
}}
outbound "direct" type="direct"
outbound "block" type="block"
outbound "upstream" type="http-connect" {{
    server host="127.0.0.1" port={proxy_port}
}}
outbound "dead" type="http-connect" {{
    server host="127.0.0.1" port={dead_port}
}}
outbound "sel" type="selector" {{
    member "upstream"
    member "direct"
    selected "upstream"
}}
routing {{
    rules {{
        - domain "sel.probe.test" to="sel"
        - domain "dead.probe.test" to="dead"
        - final "direct"
    }}
}}
''', encoding="utf-8")

            proc = subprocess.Popen(
                [str(binary), "run", "--config", str(cfg)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
            )
            try:
                for _ in range(120):
                    if proc.poll() is not None:
                        raise RuntimeError(f"nexus exited early ({proc.returncode}): {proc.stderr.read()}")
                    try:
                        st, _, _ = http_req(ctrl_port, "GET", "/v1/health", token)
                        if st == 200:
                            break
                    except OSError:
                        time.sleep(0.03)
                else:
                    raise RuntimeError("nexus HTTP control did not become healthy")

                # 1. Auth enforcement on SSE endpoints and probe endpoint
                for path in (
                    "/v1/status?stream=1",
                    "/v1/connections?stream=1",
                    f"/v1/status?stream=1&token={token}",
                    f"/v1/connections?stream=true&token={token}",
                ):
                    st, hdrs, _ = http_req(ctrl_port, "GET", path, token=None)
                    assert st == 401 and "text/event-stream" not in hdrs.get("Content-Type", ""), (path, st, hdrs)
                    st2, _, _ = http_req(ctrl_port, "GET", path, token="wrong-token-00000000000000000000")
                    assert st2 == 401, (path, st2)
                st, _, _ = http_req(ctrl_port, "POST", "/v1/outbounds/direct/probe", token=None, body="{}")
                assert st == 401, f"probe without token must 401, got {st}"

                # 2. SSE /v1/status?stream=1&interval_ms=200 + live traffic counter update
                st_sse = SseReader(ctrl_port, "/v1/status?stream=1&interval_ms=200", token)
                try:
                    assert "200 OK" in st_sse.headers and "text/event-stream" in st_sse.headers, st_sse.headers
                    ev0, data0 = st_sse.next_event(2.0)
                    assert ev0 == "status", ev0
                    j0 = json.loads(data0)
                    assert j0["state"] == "running" and j0["workers"] == 2, j0
                    base_up = int(j0["upload_bytes_total"])
                    base_down = int(j0["download_bytes_total"])

                    blob = os.urandom(16384)
                    with socks5_connect(front_port, "127.0.0.1", echo_port) as s:
                        s.sendall(blob)
                        assert recv_exact(s, len(blob)) == blob

                    saw_bytes = False
                    for _ in range(10):
                        ev, data = st_sse.next_event(2.0)
                        assert ev == "status", ev
                        jn = json.loads(data)
                        if int(jn["upload_bytes_total"]) >= base_up + len(blob) and \
                           int(jn["download_bytes_total"]) >= base_down + len(blob):
                            saw_bytes = True
                            break
                    assert saw_bytes, "SSE /v1/status did not observe proxied byte counter increase"
                finally:
                    st_sse.close()

                # 3. SSE /v1/connections?stream=true&interval_ms=200 + active connection visibility
                conn_sse = SseReader(ctrl_port, "/v1/connections?stream=true&interval_ms=200", token)
                try:
                    assert "200 OK" in conn_sse.headers and "text/event-stream" in conn_sse.headers, conn_sse.headers
                    ev0, data0 = conn_sse.next_event(2.0)
                    assert ev0 == "connections" and "connections" in json.loads(data0), (ev0, data0)

                    held = socks5_connect(front_port, "127.0.0.1", echo_port)
                    try:
                        held.sendall(b"sse-active-conn")
                        assert recv_exact(held, 15) == b"sse-active-conn"
                        saw_active = False
                        for _ in range(10):
                            ev, data = conn_sse.next_event(2.0)
                            assert ev == "connections", ev
                            conns = json.loads(data)["connections"]
                            if any(c.get("outbound") == "direct" and int(c.get("upload_bytes", 0)) >= 15 for c in conns):
                                saw_active = True
                                break
                        assert saw_active, "SSE /v1/connections did not observe active proxied session"
                    finally:
                        held.close()

                    saw_empty = False
                    for _ in range(10):
                        ev, data = conn_sse.next_event(2.0)
                        assert ev == "connections", ev
                        if len(json.loads(data)["connections"]) == 0:
                            saw_empty = True
                            break
                    assert saw_empty, "SSE /v1/connections did not drop closed connection"
                finally:
                    conn_sse.close()

                # 4. Backwards-compatible SSE /v1/logs?stream=1
                log_sse = SseReader(ctrl_port, "/v1/logs?stream=1", token)
                try:
                    assert "200 OK" in log_sse.headers and "text/event-stream" in log_sse.headers, log_sse.headers
                    ev, data = log_sse.next_event(2.0)
                    assert ev == "log" and "message" in json.loads(data), (ev, data)
                finally:
                    log_sse.close()

                # 5. Ad-hoc single-outbound delay probe (POST /v1/outbounds/{tag}/probe)
                probe_url = f"http://127.0.0.1:{probe_port}/generate_204"
                probe_500 = f"http://127.0.0.1:{probe_port}/status500"

                st, _, raw = http_req(ctrl_port, "POST", "/v1/outbounds/direct/probe", token,
                    json.dumps({"url": probe_url, "timeout_ms": 3000}))
                assert st == 200, (st, raw)
                j = json.loads(raw)
                assert j["outbound"] == "direct" and j["resolved_outbound"] == "direct" and \
                    j["state"] == "up" and isinstance(j["latency_ms"], int) and j["status_code"] == 204 and \
                    j["url"] == probe_url, j

                st, _, raw = http_req(ctrl_port, "POST", "/v1/outbounds/upstream/probe", token,
                    json.dumps({"url": probe_url, "timeout_ms": 3000}))
                assert st == 200, (st, raw)
                j = json.loads(raw)
                assert j["outbound"] == "upstream" and j["resolved_outbound"] == "upstream" and \
                    j["state"] == "up" and isinstance(j["latency_ms"], int) and j["status_code"] == 204, j

                st, _, raw = http_req(ctrl_port, "POST", "/v1/outbounds/sel/probe", token,
                    json.dumps({"url": probe_url, "timeout_ms": 3000}))
                assert st == 200, (st, raw)
                j = json.loads(raw)
                assert j["outbound"] == "sel" and j["resolved_outbound"] == "upstream" and \
                    j["state"] == "up" and j["status_code"] == 204, j

                st, _, raw = http_req(ctrl_port, "POST", "/v1/outbounds/dead/probe", token,
                    json.dumps({"url": probe_url, "timeout_ms": 400}))
                assert st == 200, (st, raw)
                j = json.loads(raw)
                assert j["outbound"] == "dead" and j["state"] == "down" and j["latency_ms"] is None, j

                st, _, raw = http_req(ctrl_port, "POST", "/v1/outbounds/direct/probe", token,
                    json.dumps({"url": probe_500, "timeout_ms": 3000}))
                assert st == 200, (st, raw)
                j = json.loads(raw)
                assert j["state"] == "down" and j["latency_ms"] is None and j.get("status_code") == 500, j

                # Error mappings: block -> 409, unknown -> 404, bad url/timeout/mode/body -> 400
                st, _, raw = http_req(ctrl_port, "POST", "/v1/outbounds/block/probe", token, json.dumps({"url": probe_url}))
                assert st == 409 and "cannot-probe-block" in raw, (st, raw)
                st, _, raw = http_req(ctrl_port, "POST", "/v1/outbounds/no-such-node/probe", token, json.dumps({"url": probe_url}))
                assert st == 404 and "unknown-outbound" in raw, (st, raw)
                st, _, raw = http_req(ctrl_port, "POST", "/v1/outbounds/direct/probe", token, json.dumps({"url": "ftp://bad.test"}))
                assert st == 400 and "invalid-probe-url" in raw, (st, raw)
                st, _, raw = http_req(ctrl_port, "POST", "/v1/outbounds/direct/probe", token, json.dumps({"timeout_ms": 0}))
                assert st == 400 and "invalid-timeout" in raw, (st, raw)
                st, _, raw = http_req(ctrl_port, "POST", "/v1/outbounds/direct/probe", token, json.dumps({"mode": "bogus"}))
                assert st == 400 and "invalid-mode" in raw, (st, raw)
                st, _, raw = http_req(ctrl_port, "POST", "/v1/outbounds/direct/probe", token, "{not-json")
                assert st == 400 and "invalid-body" in raw, (st, raw)

                # GET /v1/outbounds backwards compatibility
                st, _, raw = http_req(ctrl_port, "GET", "/v1/outbounds", token)
                assert st == 200 and any(g["name"] == "sel" for g in json.loads(raw)["groups"]), (st, raw)

                # 6. Local Unix control socket probe-outbound / probe-result
                enq = unix_control_cmd(ctrl_sock, f"probe-outbound direct {probe_url} 3000 http")
                assert "state=pending" in enq and "outbound=direct" in enq and "resolved=direct" in enq, enq
                pid_tok = [t.split("=", 1)[1] for t in enq.strip().split() if t.startswith("id=")][0]
                done_line = ""
                for _ in range(100):
                    done_line = unix_control_cmd(ctrl_sock, f"probe-result {pid_tok}")
                    if "state=up" in done_line or "state=down" in done_line:
                        break
                    time.sleep(0.02)
                assert "state=up" in done_line and "status-code=204" in done_line and f"url={probe_url}" in done_line, done_line

                print(f"WAVE 25 CONTROL SSE + AD-HOC PROBE PASSED [{binary.name}]", flush=True)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
    finally:
        echo_stop.set(); echo_srv.close()
        probe_stop.set(); probe_srv.close()
        proxy_stop.set(); proxy_srv.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", type=Path, default=None)
    ns = parser.parse_args()
    run_tests(ns.binary.resolve(strict=True) if ns.binary else find_default_binary())
