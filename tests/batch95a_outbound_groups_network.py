"""Batch 95A end-to-end tests: expected-status (#4720), url-test manual override (#4647), H2 PING (#1494)."""
import argparse
import contextlib
import http.server
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from detour_network import reserve, running
from tailscale_endpoint_network import eventually
from udp_bind_port_network import certificate

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def ctl(binary, sock, *args):
    return subprocess.run([binary, "control", str(sock), *args], capture_output=True, text=True, timeout=5)


class StatusStubHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        mode = self.server.mode
        if mode == "garbage":
            self.wfile.write(b"HTTP/1.1 ")
            self.wfile.flush()
            return
        if self.server.delay_ms:
            time.sleep(self.server.delay_ms / 1000.0)
        self.send_response(int(mode))
        self.end_headers()

    def log_message(self, *_):
        pass


@contextlib.contextmanager
def status_server(initial_mode=204, delay_ms=0):
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), StatusStubHandler) as srv:
        srv.mode = initial_mode
        srv.delay_ms = delay_ms
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            yield srv
        finally:
            srv.shutdown()
            t.join()


class MiniSocksServer:
    """Minimal SOCKS5 CONNECT proxy with configurable artificial delay for url-test ordering."""

    def __init__(self, delay_ms=0):
        self.delay_ms = delay_ms
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self.stop_event.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(3.0)
            hdr = conn.recv(2)
            if len(hdr) < 2:
                return
            conn.recv(hdr[1])
            conn.sendall(b"\x05\x00")
            req = conn.recv(4)
            if len(req) < 4 or req[1] != 1:
                return
            atyp = req[3]
            if atyp == 1:
                host = socket.inet_ntoa(conn.recv(4))
            elif atyp == 3:
                ln = conn.recv(1)[0]
                host = conn.recv(ln).decode()
            else:
                return
            port = struct.unpack("!H", conn.recv(2))[0]
            if self.delay_ms:
                time.sleep(self.delay_ms / 1000.0)
            with socket.create_connection((host, port), timeout=3.0) as up:
                conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                up.settimeout(3.0)
                data = conn.recv(4096)
                if data:
                    up.sendall(data)
                    resp = up.recv(4096)
                    if resp:
                        conn.sendall(resp)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop_event.set()
        self.sock.close()
        self.thread.join(timeout=2)


class MiniH2PingServer:
    """RFC 9113 cleartext (h2c) or TLS ALPN h2 PING responder."""

    def __init__(self, ssl_ctx=None):
        self.ssl_ctx = ssl_ctx
        self.mode = "ok"
        self.pings_answered = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self.stop_event.is_set():
            try:
                raw, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _recv_exact(self, conn, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _handle(self, raw):
        conn = raw
        try:
            raw.settimeout(3.0)
            if self.ssl_ctx is not None:
                conn = self.ssl_ctx.wrap_socket(raw, server_side=True)
                assert conn.selected_alpn_protocol() == "h2", f"expected h2 ALPN, got {conn.selected_alpn_protocol()}"
            preface = self._recv_exact(conn, len(H2_PREFACE))
            if preface != H2_PREFACE:
                return
            # Send server SETTINGS first to verify client handles SETTINGS + SETTINGS ACK properly.
            conn.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            for _ in range(8):
                hdr = self._recv_exact(conn, 9)
                if not hdr:
                    return
                length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
                ftype, flags = hdr[3], hdr[4]
                payload = self._recv_exact(conn, length) if length else b""
                if payload is None:
                    return
                if ftype == 4 and (flags & 1) == 0:
                    conn.sendall(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00")
                elif ftype == 6 and (flags & 1) == 0 and len(payload) == 8:
                    if self.mode == "goaway":
                        conn.sendall(b"\x00\x00\x08\x07\x00\x00\x00\x00\x00" + b"\x00" * 8)
                        return
                    if self.mode == "bad-opaque":
                        conn.sendall(b"\x00\x00\x08\x06\x01\x00\x00\x00\x00WRONGVAL")
                        return
                    time.sleep(0.015)
                    conn.sendall(b"\x00\x00\x08\x06\x01\x00\x00\x00\x00" + payload)
                    self.pings_answered += 1
                    try:
                        conn.shutdown(socket.SHUT_WR)
                        conn.settimeout(0.3)
                        while conn.recv(256):
                            pass
                    except (OSError, ssl.SSLError):
                        pass
                    return
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self.stop_event.set()
        self.sock.close()
        self.thread.join(timeout=2)


def test_config_validation(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-95a-cfg-") as tmp:
        bad_cases = [
            'probe-url "http://127.0.0.1:80/h"\nprobe-expected-status 99',
            'probe-url "http://127.0.0.1:80/h"\nprobe-expected-status "300..200"',
            'probe-url "http://127.0.0.1:80/h"\nprobe-mode "h2-ping"\nprobe-expected-status 204',
            'probe-url "ftp://127.0.0.1:21/h"\nprobe-mode "http"',
        ]
        for idx, snippet in enumerate(bad_cases):
            cfg = Path(tmp) / f"bad-{idx}.kdl"
            cfg.write_text(f'''schema-version 1
role "client"
inbound "in" type="socks5" {{ listen host="127.0.0.1" port=18080; authentication "none"; }}
outbound "direct" type="direct"
outbound "g" type="url-test" {{
    member "direct"
    {snippet}
}}
routing {{ final "g"; }}
''')
            res = subprocess.run([binary, "run", "--config", str(cfg)], capture_output=True, text=True, timeout=5)
            assert res.returncode != 0 and "configuration:" in res.stderr, f"expected config error for {idx}: {res.stderr}"
    print("95A config validation passed (4 invalid probe configs rejected)")


def test_expected_status_and_override(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-95a-main-") as tmp, status_server(204) as stub:
        root = Path(tmp)
        fast = MiniSocksServer(delay_ms=0)
        slow = MiniSocksServer(delay_ms=90)
        try:
            front = reserve()
            control = root / "c.sock"
            cfg = root / "cfg.kdl"
            cfg.write_text(f'''schema-version 1
role "client"
control socket="{control}"
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "fast" type="socks5" {{ server host="127.0.0.1" port={fast.port}; }}
outbound "slow" type="socks5" {{ server host="127.0.0.1" port={slow.port}; }}
outbound "strict204" type="fallback" {{
    member "direct"
    probe-url "http://127.0.0.1:{stub.server_port}/check"
    probe-expected-status 204
    probe-interval-ms 500
    probe-timeout-ms 1200
}}
outbound "auto" type="url-test" {{
    member "slow"
    member "fast"
    probe-url "http://127.0.0.1:{stub.server_port}/check"
    probe-expected-status "200..204"
    probe-interval-ms 500
    probe-timeout-ms 1200
    tolerance-ms 10
}}
routing {{ final "auto"; }}
''')
            with running([binary, "run", "--config", cfg], front, root / "proxy.log"):
                # 1. Expected-status strict 204 vs 200/403/502/garbage
                eventually(lambda: "state=up" in ctl(binary, control, "group-health", "strict204").stdout and
                           "last-status=204" in ctl(binary, control, "group-health", "strict204").stdout)
                for bad in (200, 403, 502):
                    stub.mode = bad
                    eventually(lambda b=bad: "state=down" in ctl(binary, control, "group-health", "strict204").stdout and
                               f"last-status={b}" in ctl(binary, control, "group-health", "strict204").stdout)
                stub.mode = "garbage"
                eventually(lambda: "state=down" in ctl(binary, control, "group-health", "strict204").stdout)
                stub.mode = 204
                eventually(lambda: "state=up" in ctl(binary, control, "group-health", "strict204").stdout)
                print("95A expected-status (#4720) passed: 204 up, 200/403/502/garbage down")

                # 2. url-test auto selects fast -> manual override to slow -> stays locked across probes -> --auto restores fast
                eventually(lambda: "group=auto mode=url-test selected=fast\n" in ctl(binary, control, "group-health", "auto").stdout)
                sel = ctl(binary, control, "select", "auto", "slow")
                assert sel.returncode == 0 and "selected=slow override=1" in sel.stdout, sel.stdout + sel.stderr
                assert "selected=slow override=1" in ctl(binary, control, "status").stdout
                time.sleep(1.3)  # >2 probe intervals; must NOT revert manual override
                gh = ctl(binary, control, "group-health", "auto").stdout
                assert "selected=slow override=1" in gh, gh
                assert "member=fast state=up" in gh and "member=slow state=up" in gh, gh

                rst = ctl(binary, control, "select", "auto", "--auto")
                assert rst.returncode == 0 and "selected=fast override=0" in rst.stdout, rst.stdout + rst.stderr
                gh2 = ctl(binary, control, "group-health", "auto").stdout
                assert "selected=fast\n" in gh2 and "override=1" not in gh2, gh2
                print("95A url-test manual override & --auto reset (#4647) passed")
        finally:
            fast.close()
            slow.close()


def test_h2_ping(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-95a-h2-") as tmp:
        root = Path(tmp)
        certificate(root)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(["h2"])
        ctx.load_cert_chain(str(root / "cert"), str(root / "key"))

        h2c_srv = MiniH2PingServer(ssl_ctx=None)
        h2_tls_srv = MiniH2PingServer(ssl_ctx=ctx)
        try:
            front = reserve()
            control = root / "c.sock"
            cfg = root / "h2.kdl"
            cfg.write_text(f'''schema-version 1
role "client"
control socket="{control}"
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "h2c" type="fallback" {{
    member "direct"
    probe-mode "h2-ping"
    probe-url "http://127.0.0.1:{h2c_srv.port}/"
    probe-interval-ms 500
    probe-timeout-ms 1200
}}
outbound "h2tls" type="fallback" {{
    member "direct"
    probe-mode "h2-ping"
    probe-url "https://127.0.0.1:{h2_tls_srv.port}/"
    probe-server-name "localhost"
    probe-ca-file "{root / "cert"}"
    probe-interval-ms 500
    probe-timeout-ms 1200
}}
routing {{ final "h2tls"; }}
''')
            with running([binary, "run", "--config", cfg], front, root / "h2.log"):
                eventually(lambda: "state=up" in ctl(binary, control, "group-health", "h2c").stdout and
                           "latency-ms=" in ctl(binary, control, "group-health", "h2c").stdout)
                eventually(lambda: "state=up" in ctl(binary, control, "group-health", "h2tls").stdout and
                           "latency-ms=" in ctl(binary, control, "group-health", "h2tls").stdout)
                assert h2c_srv.pings_answered >= 1 and h2_tls_srv.pings_answered >= 1

                h2c_srv.mode = "bad-opaque"
                eventually(lambda: "state=down" in ctl(binary, control, "group-health", "h2c").stdout)
                h2_tls_srv.mode = "goaway"
                eventually(lambda: "state=down" in ctl(binary, control, "group-health", "h2tls").stdout)

                h2c_srv.mode = "ok"
                h2_tls_srv.mode = "ok"
                eventually(lambda: "state=up" in ctl(binary, control, "group-health", "h2c").stdout)
                eventually(lambda: "state=up" in ctl(binary, control, "group-health", "h2tls").stdout)
                print("95A HTTP/2 PING probe (#1494) passed for both h2c and TLS ALPN h2")
        finally:
            h2c_srv.close()
            h2_tls_srv.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    args = parser.parse_args()
    test_config_validation(args.binary)
    test_expected_status_and_override(args.binary)
    test_h2_ping(args.binary)


if __name__ == "__main__":
    main()
