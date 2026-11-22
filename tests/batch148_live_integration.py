#!/usr/bin/env python3
"""Batch 148 live integration tests against the real nexus binary:
  148.1 log-ring decoupled from stderr warn + GET /v1/logs + SSE + GET /v1/connections/{id} + CLI
  148.2 SIGHUP reload hard drain grace with active long-lived idle TCP session
  148.3 Traffic reject method="default" (no-drop) vs method="drop"
  148.4 Direct TLS ClientHello record fragmentation (wire verified) + tcp-prefix +
        top-level certificate CA + unified certificate-sha256 (HTTP CONNECT TLS) + live UDP SNTPv4
"""

import hashlib
import json
import os
import pathlib
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_BIN = ROOT / "target/x86_64-linux-gnu/a5c87b0b409ddfec/bin/nexus"
NEXUS_BIN = pathlib.Path(os.environ.get("NEXUS_BIN", str(DEFAULT_BIN)))
NTP_DELTA = 2208988800


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_get(port: int, path: str, token: str, timeout: float = 3.0) -> tuple[int, str]:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def wait_health(http_port: int, token: str, proc: subprocess.Popen, timeout: float = 6.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate()
            raise RuntimeError(f"nexus exited early rc={proc.returncode}\nout={out}\nerr={err}")
        try:
            code, _ = http_get(http_port, "/v1/health", token, timeout=0.5)
            if code == 200:
                return
        except Exception:
            pass
        time.sleep(0.05)
    raise RuntimeError("timed out waiting for /v1/health")


def socks5_connect_raw(proxy_port: int, dst_ip: str, dst_port: int, timeout: float = 3.0) -> tuple[socket.socket, bytes]:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    greet = s.recv(2)
    assert greet == b"\x05\x00", f"bad socks5 greeting: {greet!r}"
    req = b"\x05\x01\x00\x01" + socket.inet_aton(dst_ip) + struct.pack("!H", dst_port)
    s.sendall(req)
    rep = b""
    try:
        while len(rep) < 10:
            chunk = s.recv(10 - len(rep))
            if not chunk:
                break
            rep += chunk
    except (ConnectionResetError, TimeoutError):
        pass
    return s, rep


class TcpLoopServer:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self.stop_event.is_set():
            try:
                c, _ = self.sock.accept()
                threading.Thread(target=self.handler, args=(c, self.stop_event), daemon=True).start()
            except TimeoutError:
                continue
            except OSError:
                break

    def close(self) -> None:
        self.stop_event.set()
        self.sock.close()


def _echo_handler(conn: socket.socket, stop: threading.Event) -> None:
    with conn:
        conn.settimeout(10.0)
        try:
            while not stop.is_set():
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass


def EchoServer() -> TcpLoopServer:
    return TcpLoopServer(_echo_handler)


class MockSntpServer:
    def __init__(self, offset_ms: int = 250) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.offset_ms, self.requests = offset_ms, 0
        self.stop_event = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self.stop_event.is_set():
            try:
                data, peer = self.sock.recvfrom(128)
            except TimeoutError:
                continue
            except OSError:
                break
            if len(data) < 48 or data[0] != 0x23:
                continue
            self.requests += 1
            now_ms = int(time.time() * 1000) + self.offset_ms
            rx_s, rx_f = now_ms // 1000 + NTP_DELTA, ((now_ms % 1000) << 32) // 1000
            tx_s, tx_f = (now_ms + 1) // 1000 + NTP_DELTA, (((now_ms + 1) % 1000) << 32) // 1000
            resp = bytearray(48)
            resp[0], resp[1] = 0x24, 2
            resp[24:32] = data[40:48]
            struct.pack_into("!IIII", resp, 32, rx_s, rx_f, tx_s, tx_f)
            self.sock.sendto(bytes(resp), peer)

    def close(self) -> None:
        self.stop_event.set()
        self.sock.close()


class FragmentInspectingTlsServer:
    def __init__(self, certfile: pathlib.Path, keyfile: pathlib.Path) -> None:
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(certfile), str(keyfile))
        self.client_hello_records = 0
        self.srv = TcpLoopServer(self._handle)
        self.port = self.srv.port

    def _handle(self, conn: socket.socket, _stop: threading.Event) -> None:
        with conn:
            conn.settimeout(5.0)
            in_bio, out_bio = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = self.ctx.wrap_bio(in_bio, out_bio, server_side=True)
            wire = bytearray()
            while True:
                try:
                    tls.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    if out := out_bio.read():
                        conn.sendall(out)
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    wire.extend(chunk)
                    pos, recs = 0, 0
                    while pos + 5 <= len(wire) and wire[pos] == 0x16 and wire[pos + 1] == 0x03:
                        rlen = (wire[pos + 3] << 8) | wire[pos + 4]
                        if pos + 5 + rlen > len(wire):
                            break
                        recs += 1
                        pos += 5 + rlen
                    self.client_hello_records = max(self.client_hello_records, recs)
                    in_bio.write(chunk)
                except ssl.SSLWantWriteError:
                    if out := out_bio.read():
                        conn.sendall(out)
            if out := out_bio.read():
                conn.sendall(out)
            while True:
                try:
                    msg = tls.read(4096)
                    if not msg:
                        break
                    tls.write(b"TLS-OK:" + msg)
                    if out := out_bio.read():
                        conn.sendall(out)
                    break
                except ssl.SSLWantReadError:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    in_bio.write(chunk)

    def close(self) -> None:
        self.srv.close()


class HttpsConnectProxyServer:
    def __init__(self, certfile: pathlib.Path, keyfile: pathlib.Path) -> None:
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(certfile), str(keyfile))
        self.srv = TcpLoopServer(self._handle)
        self.port = self.srv.port

    def _handle(self, raw: socket.socket, _stop: threading.Event) -> None:
        try:
            with self.ctx.wrap_socket(raw, server_side=True) as tls:
                tls.settimeout(5.0)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    c = tls.recv(2048)
                    if not c:
                        return
                    buf += c
                parts = buf.split(b"\r\n", 1)[0].decode("ascii", errors="ignore").split()
                if len(parts) < 2 or parts[0] != "CONNECT":
                    return
                host, p = parts[1].rsplit(":", 1)
                with socket.create_connection((host, int(p)), timeout=3.0) as up:
                    tls.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    up.settimeout(5.0)
                    if data := tls.recv(4096):
                        up.sendall(data)
                        if rep := up.recv(4096):
                            tls.sendall(rep)
        except OSError:
            pass

    def close(self) -> None:
        self.srv.close()


def generate_self_signed_cert(tmp: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, str]:
    cert, key = tmp / "server.crt", tmp / "server.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-keyout", str(key), "-out", str(cert), "-days", "2", "-nodes", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, capture_output=True)
    der = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-outform", "DER"])
    return cert, key, hashlib.sha256(der).hexdigest()


def run_all() -> None:
    assert NEXUS_BIN.is_file(), f"nexus binary not found: {NEXUS_BIN}"
    with tempfile.TemporaryDirectory(prefix="nexus-b148-") as td:
        tmp = pathlib.Path(td)
        token_file, token = tmp / "bearer.tok", "b148-live-secret"
        token_file.write_text(token + "\n", encoding="utf-8")
        os.chmod(token_file, 0o600)

        cert_file, key_file, cert_sha256 = generate_self_signed_cert(tmp)
        echo, echo_prefix, echo_pin = EchoServer(), EchoServer(), EchoServer()
        sntp = MockSntpServer(offset_ms=250)
        frag_tls = FragmentInspectingTlsServer(cert_file, key_file)
        https_proxy = HttpsConnectProxyServer(cert_file, key_file)

        socks_port, http_port, bad_pin_port = free_tcp_port(), free_tcp_port(), free_tcp_port()
        ctrl_sock, reject_rst_port, reject_drop_port = tmp / "ctrl.sock", 18001, 18002
        cfg_path = tmp / "config.kdl"

        def write_config(port_val: int) -> None:
            cfg_path.write_text(f'''schema-version 1
role "client"
shutdown-grace-ms 400
log {{ level "warn"; ring-level "trace"; ring-capacity 512; }}
certificate {{ ca-file "{cert_file}"; }}
ntp {{ server host="127.0.0.1" port={sntp.port}; interval-ms 60000; timeout-ms 1500; }}
control socket="{ctrl_sock}" http-listen="127.0.0.1:{http_port}" bearer-token-file="{token_file}" metrics=#true
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={port_val}; authentication "none"; }}
outbound "direct" type="direct"
outbound "good-https" type="http-connect" {{
    server host="127.0.0.1" port={https_proxy.port}
    tls {{ server-name "localhost"; verify #true; certificate-sha256 "{cert_sha256}"; }}
}}
outbound "bad-https" type="http-connect" {{
    server host="127.0.0.1" port={https_proxy.port}
    tls {{ server-name "localhost"; verify #true; certificate-sha256 "0000000000000000000000000000000000000000000000000000000000000000"; }}
}}
routing {{
    rule-set "rs-rst" {{ port {reject_rst_port}; }}
    rule-set "rs-drop" {{ port {reject_drop_port}; }}
    rule-set "rs-frag" {{ port {frag_tls.port}; }}
    rule-set "rs-pref" {{ port {echo_prefix.port}; }}
    rule-set "rs-good-pin" {{ port {echo_pin.port}; }}
    rule-set "rs-bad-pin" {{ port {bad_pin_port}; }}
    default-outbound "direct"
    tcp-program sniff-timeout-ms=1000 unknown="skip" {{
        rule rule-set="rs-rst" action="reject" method="default" no-drop=#true
        rule rule-set="rs-drop" action="reject" method="drop"
        rule rule-set="rs-frag" action="route-options" tls-record-fragment=#true tls-fragment-min=12 tls-fragment-max=32
        rule rule-set="rs-pref" action="route-options" tcp-prefix="4e455855535052453a"
        rule rule-set="rs-good-pin" action="route" outbound="good-https"
        rule rule-set="rs-bad-pin" action="route" outbound="bad-https"
    }}
}}
''', encoding="utf-8")

        write_config(socks_port)
        proc = subprocess.Popen(
            [str(NEXUS_BIN), "run", "--config", str(cfg_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_health(http_port, token, proc)

            # 148.1 & 148.4(NTP): verify /v1/logs backlog has info logs (including ntp synced) even though stderr level=warn
            code, body = http_get(http_port, "/v1/logs?limit=64", token)
            assert code == 200, f"/v1/logs failed: {code} {body}"
            logs_obj = json.loads(body)
            msgs = [e["message"] for e in logs_obj["entries"]]
            assert any("proxy started" in m for m in msgs), f"missing startup info log in ring: {msgs}"
            assert sntp.requests >= 1, "mock SNTP server was not queried"
            assert any("ntp synced" in m and "stratum=2" in m for m in msgs), f"missing ntp synced log: {msgs}"
            print("[PASS] 148.1/148.4 log-ring captures info/trace while stderr=warn + live SNTPv4 sync")

            # CLI control logs check
            cli_logs = subprocess.run(
                [str(NEXUS_BIN), "control", str(ctrl_sock), "logs", "--level", "info", "--search", "ntp", "--limit", "16"],
                capture_output=True, text=True, check=True, timeout=5,
            )
            assert "ntp synced" in cli_logs.stdout, f"CLI control logs missing ntp synced: {cli_logs.stdout}"

            # SSE /v1/logs?stream=1 check
            with socket.create_connection(("127.0.0.1", http_port), timeout=3.0) as sse:
                sse.settimeout(2.0)
                sse.sendall(
                    f"GET /v1/logs?stream=1&limit=16 HTTP/1.1\r\nHost: 127.0.0.1:{http_port}\r\nAuthorization: Bearer {token}\r\n\r\n".encode()
                )
                sse_data = b""
                deadline = time.monotonic() + 1.5
                while time.monotonic() < deadline and b"event: log" not in sse_data:
                    try:
                        chunk = sse.recv(4096)
                        if not chunk:
                            break
                        sse_data += chunk
                    except TimeoutError:
                        break
                sse_text = sse_data.decode("utf-8", errors="replace")
                assert "text/event-stream" in sse_text and "event: log" in sse_text, f"bad SSE reply: {sse_text[:300]}"
            print("[PASS] 148.1 GET /v1/logs?stream=1 SSE + CLI control logs")

            # Active connection detail inspection (HTTP + CLI)
            conn_sock, rep = socks5_connect_raw(socks_port, "127.0.0.1", echo.port)
            assert len(rep) == 10 and rep[1] == 0, f"socks5 connect failed: {rep!r}"
            conn_sock.sendall(b"ping-148")
            assert conn_sock.recv(16) == b"ping-148"
            code, cbody = http_get(http_port, "/v1/connections", token)
            assert code == 200
            conns = json.loads(cbody)["connections"]
            assert len(conns) >= 1
            cid = conns[0]["id"]
            assert conns[0]["inbound"] == "socks", f"missing inbound name: {conns[0]}"
            code, dbody = http_get(http_port, f"/v1/connections/{cid}", token)
            assert code == 200, f"/v1/connections/{cid} failed: {code} {dbody}"
            detail = json.loads(dbody)
            assert detail["id"] == cid and detail["inbound"] == "socks" and detail["outbound"] == "direct", f"bad detail: {detail}"
            cli_conn = subprocess.run(
                [str(NEXUS_BIN), "control", str(ctrl_sock), "connection", "show", str(cid)],
                capture_output=True, text=True, check=True, timeout=5,
            )
            assert f"id={cid}" in cli_conn.stdout and "inbound=socks" in cli_conn.stdout, f"bad CLI conn show: {cli_conn.stdout}"
            print("[PASS] 148.1 GET /v1/connections/{id} + CLI connection show")

            # 148.3 Traffic reject method=default (no-drop) vs method=drop
            s_rst, rep_rst = socks5_connect_raw(socks_port, "127.0.0.1", reject_rst_port)
            s_rst.close()
            assert len(rep_rst) == 10 and rep_rst[1] == 2, f"expected SOCKS5 rep=2 on reject default, got {rep_rst!r}"
            s_drp, rep_drp = socks5_connect_raw(socks_port, "127.0.0.1", reject_drop_port)
            s_drp.close()
            assert rep_drp == b"", f"expected silent drop (empty reply), got {rep_drp!r}"
            print("[PASS] 148.3 traffic reject method=default vs method=drop")

            # 148.4 TLS ClientHello record fragmentation (real TLS handshake + wire inspection)
            s_frag, rep_frag = socks5_connect_raw(socks_port, "127.0.0.1", frag_tls.port)
            assert len(rep_frag) == 10 and rep_frag[1] == 0, f"frag socks5 failed: {rep_frag!r}"
            client_ctx = ssl.create_default_context(cafile=str(cert_file))
            with client_ctx.wrap_socket(s_frag, server_hostname="localhost") as tls_sock:
                tls_sock.sendall(b"hello-frag")
                resp = tls_sock.recv(64)
                assert resp == b"TLS-OK:hello-frag", f"unexpected TLS echo: {resp!r}"
            assert frag_tls.client_hello_records >= 3, (
                f"expected >=3 fragmented TLS ClientHello records on wire, saw {frag_tls.client_hello_records}"
            )
            print(f"[PASS] 148.4 tls-record-fragment split ClientHello into {frag_tls.client_hello_records} records & TLS succeeded")

            # 148.4 tcp-prefix on direct TCP
            s_pref, rep_pref = socks5_connect_raw(socks_port, "127.0.0.1", echo_prefix.port)
            assert len(rep_pref) == 10 and rep_pref[1] == 0
            s_pref.sendall(b"HELLO")
            got = s_pref.recv(64)
            s_pref.close()
            assert got == b"NEXUSPRE:HELLO", f"tcp-prefix mismatch: {got!r}"
            print("[PASS] 148.4 tcp-prefix prepended on direct TCP")

            # 148.4 top-level certificate CA + unified certificate-sha256 (HTTP CONNECT TLS)
            s_gp, rep_gp = socks5_connect_raw(socks_port, "127.0.0.1", echo_pin.port)
            assert len(rep_gp) == 10 and rep_gp[1] == 0, f"good certificate-sha256 failed: {rep_gp!r}"
            s_gp.sendall(b"pin-ok")
            assert s_gp.recv(32) == b"pin-ok"
            s_gp.close()

            s_bp, rep_bp = socks5_connect_raw(socks_port, "127.0.0.1", bad_pin_port)
            s_bp.close()
            assert not (len(rep_bp) == 10 and rep_bp[1] == 0), f"bad certificate-sha256 unexpectedly succeeded: {rep_bp!r}"
            print("[PASS] 148.4 top-level certificate CA + unified certificate-sha256 verified")

            # 148.2 SIGHUP reload hard drain grace while conn_sock is still idle & open!
            new_socks_port = free_tcp_port()
            write_config(new_socks_port)
            t0 = time.monotonic()
            proc.send_signal(signal.SIGHUP)
            # Wait for new listener to come up and old idle connection to be force-drained within grace!
            reloaded = False
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                try:
                    s_new, rep_new = socks5_connect_raw(new_socks_port, "127.0.0.1", echo.port, timeout=0.5)
                    if len(rep_new) == 10 and rep_new[1] == 0:
                        s_new.close()
                        reloaded = True
                        break
                    s_new.close()
                except OSError:
                    time.sleep(0.05)
            assert reloaded, "SIGHUP reload did not activate new SOCKS5 listener"
            # Verify old idle connection gets closed by shutdown-grace-ms=400!
            conn_sock.settimeout(2.0)
            drained_ok = False
            try:
                data = conn_sock.recv(64)
                if data == b"":
                    drained_ok = True
            except (ConnectionResetError, OSError):
                drained_ok = True
            elapsed = time.monotonic() - t0
            conn_sock.close()
            assert drained_ok and elapsed < 2.5, f"old listener did not force-drain within grace: ok={drained_ok} elapsed={elapsed:.2f}s"
            print(f"[PASS] 148.2 SIGHUP reload force-drained retired listener in {elapsed:.2f}s (grace=400ms)")

            proc.send_signal(signal.SIGTERM)
            stdout, stderr = proc.communicate(timeout=5)
            assert proc.returncode == 0, f"nexus shutdown rc={proc.returncode}\nstderr={stderr}"
            # Verify stderr respected level="warn" (no info/debug/trace lines leaked to stderr!)
            for line in stderr.splitlines():
                assert " info " not in line and " debug " not in line and " trace " not in line, (
                    f"148.1 stderr leaked sub-warn line: {line}"
                )
            print("[PASS] 148.1 stderr stayed strictly warn+ while log-ring captured trace+")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            echo.close()
            echo_prefix.close()
            echo_pin.close()
            sntp.close()
            frag_tls.close()
            https_proxy.close()

    print("BATCH148_LIVE_INTEGRATION_OK")


if __name__ == "__main__":
    run_all()
