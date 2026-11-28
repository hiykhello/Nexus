#!/usr/bin/env python3
"""Wave 25 Track D: Sustained soak/handover/SSE/probe stability + FD/RSS zero-leak suite (~18s)."""
import argparse
import hashlib
import http.client
import json
import os
import secrets
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def reserve_port(udp: bool = False) -> int:
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def find_default_binary() -> Path:
    if env_bin := os.environ.get("NEXUS_BIN"):
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


def socks5_tcp(proxy_port: int, dst_ip: str, dst_port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
    s.settimeout(6.0)
    s.sendall(b"\x05\x01\x00")
    assert recv_exact(s, 2) == b"\x05\x00"
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(dst_ip) + struct.pack("!H", dst_port))
    rep = recv_exact(s, 10)
    assert rep[0] == 5 and rep[1] == 0, f"SOCKS5 TCP failed: {rep!r}"
    return s


def socks5_udp_open(proxy_port: int) -> tuple[socket.socket, socket.socket, tuple[str, int]]:
    ctrl = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
    ctrl.settimeout(5.0)
    ctrl.sendall(b"\x05\x01\x00")
    assert recv_exact(ctrl, 2) == b"\x05\x00"
    ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    hdr = recv_exact(ctrl, 4)
    assert hdr[0] == 5 and hdr[1] == 0, f"SOCKS5 UDP associate failed: {hdr!r}"
    ip = socket.inet_ntoa(recv_exact(ctrl, 4)) if hdr[3] == 1 else socket.inet_ntop(socket.AF_INET6, recv_exact(ctrl, 16))
    port = struct.unpack("!H", recv_exact(ctrl, 2))[0]
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(4.0)
    return ctrl, u, ("127.0.0.1" if ip in ("0.0.0.0", "::") else ip, port)


def http_req(port: int, method: str, path: str, token: str, body: str | None = None) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=8.0)
    hdrs = {"Authorization": f"Bearer {token}"}
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=body.encode("utf-8") if body is not None else None, headers=hdrs)
        r = conn.getresponse()
        return r.status, r.read().decode("utf-8", errors="replace")
    finally:
        conn.close()


def proc_stats(pid: int) -> tuple[int, float]:
    fds = len(os.listdir(f"/proc/{pid}/fd"))
    rss_kb = 0
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            rss_kb = int(line.split()[1])
    return fds, rss_kb / 1024.0


def build_dns_query(txid: int, name: str) -> bytes:
    q = bytearray()
    for lbl in name.strip(".").split("."):
        b = lbl.encode("ascii")
        q.append(len(b)); q.extend(b)
    q.append(0)
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + bytes(q) + struct.pack("!HH", 1, 1)


def start_tcp_server(handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(256)
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
        c.settimeout(8.0)
        while d := c.recv(32768):
            c.sendall(d)
    except OSError:
        pass
    finally:
        c.close()


def handle_probe_http(c: socket.socket):
    try:
        c.settimeout(2.0)
        c.recv(1024)
        c.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except OSError:
        pass
    finally:
        c.close()


def start_udp_service(reply_fn):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    stop = threading.Event()

    def serve():
        s.settimeout(0.2)
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(65535)
                if (resp := reply_fn(data)) is not None:
                    s.sendto(resp, addr)
            except TimeoutError:
                continue
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return s, s.getsockname()[1], stop


def dns_reply_a_loopback(req: bytes) -> bytes | None:
    if len(req) < 12:
        return None
    pos = 12
    while pos < len(req) and req[pos] != 0:
        pos += 1 + req[pos]
    qend = pos + 5
    if qend > len(req):
        return None
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 5, 4) + socket.inet_aton("127.0.0.1")
    return req[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + req[12:qend] + ans


def run_soak(binary: Path, duration_s: float) -> None:
    tsrv, tport, tstop = start_tcp_server(handle_tcp_echo)
    psrv, pport, pstop = start_tcp_server(handle_probe_http)
    usrv, uport, ustop = start_udp_service(lambda d: d)
    dsrv, dport, dstop = start_udp_service(dns_reply_a_loopback)
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-w25-soak-") as tmpdir:
            root = Path(tmpdir)
            front, ctrl, dns_port = reserve_port(), reserve_port(), reserve_port(udp=True)
            while ctrl == front:
                ctrl = reserve_port()
            token = secrets.token_hex(24)
            token_file = root / "token"
            token_file.write_text(token + "\n", encoding="utf-8")
            os.chmod(token_file, 0o600)
            rules = root / "rules.kdl"
            rules.write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="blocked0.soak.test"\n', encoding="utf-8")
            cfg = root / "soak.kdl"
            cfg.write_text(f'''schema-version 1
role "client"
workers 2
tcp-splice-pipes 16
shutdown-grace-ms 400
control http-listen="127.0.0.1:{ctrl}" bearer-token-file="{token_file}" metrics=#true
dns {{
    listen host="127.0.0.1" port={dns_port}
    server "up" type="udp" host="127.0.0.1" port={dport}
    final "up"
}}
inbound "mixed" type="mixed" {{
    listen host="127.0.0.1" port={front}
    authentication "none"
}}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{
    rulesets {{ "dyn" path="{rules}" format="kdl"; }}
    rules {{ - rule-set="dyn" to="reject"; }}
    final "direct"
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
                        if http_req(ctrl, "GET", "/v1/health", token)[0] == 200:
                            break
                    except OSError:
                        time.sleep(0.03)
                else:
                    raise RuntimeError("nexus did not become healthy")

                # Warmup TCP, UDP, DNS, and ad-hoc probe before recording baseline FDs/RSS
                for _ in range(4):
                    with socks5_tcp(front, "127.0.0.1", tport) as s:
                        s.sendall(b"warmup"); assert recv_exact(s, 6) == b"warmup"
                c_u, u_s, relay_ep = socks5_udp_open(front)
                try:
                    pkt = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", uport) + b"wu"
                    u_s.sendto(pkt, relay_ep); assert u_s.recv(4096) == pkt
                finally:
                    u_s.close(); c_u.close()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ds:
                    ds.settimeout(3.0)
                    ds.sendto(build_dns_query(0x1234, "warm.soak.test"), ("127.0.0.1", dns_port))
                    assert ds.recv(4096)[-4:] == socket.inet_aton("127.0.0.1")
                probe_url = f"http://127.0.0.1:{pport}/generate_204"
                st, raw = http_req(ctrl, "POST", "/v1/outbounds/direct/probe", token,
                    json.dumps({"url": probe_url, "timeout_ms": 3000}))
                assert st == 200 and json.loads(raw)["state"] == "up", (st, raw)

                time.sleep(0.25)
                base_fds, base_rss = proc_stats(proc.pid)

                stop_flag = threading.Event()
                errors: list[str] = []
                lock = threading.Lock()
                counts = {"tcp": 0, "udp": 0, "dns": 0, "sse_status": 0, "sse_conn": 0, "reloads": 0, "probes": 0}

                def fail(msg: str):
                    with lock:
                        errors.append(msg)

                def bump(key: str):
                    with lock:
                        counts[key] += 1

                def tcp_worker(wid: int):
                    while not stop_flag.is_set():
                        try:
                            blob = os.urandom(16384)
                            with socks5_tcp(front, "127.0.0.1", tport) as s:
                                s.sendall(blob); got = recv_exact(s, len(blob))
                            if hashlib.sha256(got).digest() != hashlib.sha256(blob).digest():
                                fail(f"tcp-{wid}: digest mismatch"); return
                            bump("tcp")
                        except OSError as exc:
                            if not stop_flag.is_set():
                                fail(f"tcp-{wid}: {exc}"); return

                def udp_worker(wid: int):
                    while not stop_flag.is_set():
                        c_s = u_sock = None
                        try:
                            c_s, u_sock, relay = socks5_udp_open(front)
                            for i in range(4):
                                msg = f"u-{wid}-{i}-".encode() + os.urandom(16)
                                pkt = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", uport) + msg
                                u_sock.sendto(pkt, relay)
                                if u_sock.recv(4096) != pkt:
                                    fail(f"udp-{wid}: echo mismatch"); return
                                bump("udp")
                        except OSError as exc:
                            if not stop_flag.is_set():
                                fail(f"udp-{wid}: {exc}"); return
                        finally:
                            if u_sock: u_sock.close()
                            if c_s: c_s.close()

                def dns_worker():
                    seq = 1
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ds:
                        ds.settimeout(3.0)
                        while not stop_flag.is_set():
                            try:
                                txid = (seq % 65000) + 1
                                ds.sendto(build_dns_query(txid, f"h{seq % 32}.soak.test"), ("127.0.0.1", dns_port))
                                ans = ds.recv(4096)
                                if ans[:2] != struct.pack("!H", txid) or ans[-4:] != socket.inet_aton("127.0.0.1"):
                                    fail(f"dns: bad answer for txid {txid}"); return
                                seq += 1; bump("dns"); time.sleep(0.02)
                            except OSError as exc:
                                if not stop_flag.is_set():
                                    fail(f"dns: {exc}"); return

                def sse_worker(path: str, expected_ev: str, key: str):
                    while not stop_flag.is_set():
                        sock = None
                        try:
                            sock = socket.create_connection(("127.0.0.1", ctrl), timeout=4.0)
                            sock.settimeout(1.5)
                            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{ctrl}\r\nAuthorization: Bearer {token}\r\n\r\n".encode("ascii"))
                            buf = b""
                            while b"\r\n\r\n" not in buf and not stop_flag.is_set():
                                ch = sock.recv(4096)
                                if not ch: break
                                buf += ch
                            if b"\r\n\r\n" not in buf: continue
                            hdr, buf = buf.split(b"\r\n\r\n", 1)
                            if b"text/event-stream" not in hdr:
                                fail(f"sse {path}: missing text/event-stream"); return
                            frames = 0
                            while not stop_flag.is_set() and frames < 10:
                                while b"\n\n" in buf:
                                    blk, buf = buf.split(b"\n\n", 1)
                                    txt = blk.decode("utf-8", errors="replace")
                                    if not txt or txt.startswith(":"): continue
                                    ev = dat = ""
                                    for ln in txt.split("\n"):
                                        if ln.startswith("event: "): ev = ln[7:]
                                        elif ln.startswith("data: "): dat = ln[6:]
                                    if ev != expected_ev:
                                        fail(f"sse {path}: unexpected event {ev!r}"); return
                                    json.loads(dat); frames += 1; bump(key)
                                try:
                                    ch = sock.recv(8192)
                                    if not ch: break
                                    buf += ch
                                except TimeoutError:
                                    continue
                        except OSError as exc:
                            if not stop_flag.is_set():
                                fail(f"sse {path}: {exc}"); return
                        finally:
                            if sock: sock.close()

                def control_worker():
                    step = 0
                    while not stop_flag.is_set():
                        try:
                            step += 1
                            rules.write_text(f'schema-version 2\nkind "predicate"\nrule type="domain" value="blocked{step}.soak.test"\n', encoding="utf-8")
                            if step % 2 == 1:
                                st, raw = http_req(ctrl, "POST", "/v1/reload", token, "{}")
                                if st not in (200, 202, 409):
                                    fail(f"reload HTTP {st}: {raw}"); return
                            else:
                                proc.send_signal(signal.SIGHUP)
                            bump("reloads")
                            st, raw = http_req(ctrl, "POST", "/v1/network-change", token, "{}")
                            if st != 200:
                                fail(f"network-change {st}: {raw}"); return
                            st, raw = http_req(ctrl, "POST", "/v1/outbounds/direct/probe", token,
                                json.dumps({"url": probe_url, "timeout_ms": 3000}))
                            if st != 200 or json.loads(raw).get("state") != "up":
                                fail(f"probe {st}: {raw}"); return
                            bump("probes"); time.sleep(0.35)
                        except OSError as exc:
                            if not stop_flag.is_set():
                                fail(f"control: {exc}"); return

                threads = [
                    *(threading.Thread(target=tcp_worker, args=(i,), daemon=True) for i in range(4)),
                    *(threading.Thread(target=udp_worker, args=(i,), daemon=True) for i in range(2)),
                    threading.Thread(target=dns_worker, daemon=True),
                    threading.Thread(target=sse_worker, args=("/v1/status?stream=1&interval_ms=200", "status", "sse_status"), daemon=True),
                    threading.Thread(target=sse_worker, args=("/v1/connections?stream=1&interval_ms=200", "connections", "sse_conn"), daemon=True),
                    threading.Thread(target=control_worker, daemon=True),
                ]
                for t in threads:
                    t.start()

                peak_fds, peak_rss = base_fds, base_rss
                deadline = time.monotonic() + duration_s
                while time.monotonic() < deadline:
                    assert proc.poll() is None, f"nexus crashed mid-soak ({proc.returncode}): {proc.stderr.read()}"
                    with lock:
                        if errors: break
                    cur_fds, cur_rss = proc_stats(proc.pid)
                    peak_fds, peak_rss = max(peak_fds, cur_fds), max(peak_rss, cur_rss)
                    time.sleep(0.5)

                stop_flag.set()
                for t in threads:
                    t.join(timeout=6.0)
                assert not errors, f"soak worker errors: {errors[:5]}"
                assert proc.poll() is None, f"nexus exited unexpectedly ({proc.returncode})"
                assert counts["tcp"] >= 20 and counts["udp"] >= 20 and counts["dns"] >= 20, counts
                assert counts["sse_status"] >= 10 and counts["sse_conn"] >= 10, counts
                assert counts["reloads"] >= 4 and counts["probes"] >= 4, counts

                time.sleep(0.8)
                end_fds, end_rss = proc_stats(proc.pid)
                fd_delta, rss_delta = end_fds - base_fds, end_rss - base_rss
                assert fd_delta <= 2, f"FD leak: base={base_fds} peak={peak_fds} end={end_fds} delta={fd_delta}"
                assert rss_delta <= 32.0 and end_rss <= 80.0, f"RSS growth: base={base_rss:.2f} peak={peak_rss:.2f} end={end_rss:.2f} MiB"

                with socks5_tcp(front, "127.0.0.1", tport) as s:
                    s.sendall(b"post-soak-ok"); assert recv_exact(s, 12) == b"post-soak-ok"
                st, raw = http_req(ctrl, "POST", "/v1/outbounds/direct/probe", token,
                    json.dumps({"url": probe_url, "timeout_ms": 3000}))
                assert st == 200 and json.loads(raw)["state"] == "up", (st, raw)

                proc.terminate()
                rc = proc.wait(timeout=5)
                assert rc == 0, f"expected clean exit 0, got {rc}: {proc.stderr.read()}"
                print(
                    f"WAVE 25 SOAK STABILITY PASSED [{binary.name}] ({duration_s:.1f}s): "
                    f"FDs {base_fds}->{peak_fds}->{end_fds} (delta={fd_delta}), "
                    f"VmRSS {base_rss:.2f}->{peak_rss:.2f}->{end_rss:.2f} MiB, counts={counts}",
                    flush=True,
                )
            finally:
                if proc.poll() is None:
                    proc.kill(); proc.wait(timeout=5)
    finally:
        for ev, sock in ((tstop, tsrv), (pstop, psrv), (ustop, usrv), (dstop, dsrv)):
            ev.set(); sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", type=Path, default=None)
    parser.add_argument("--duration", type=float, default=15.0)
    ns = parser.parse_args()
    run_soak(ns.binary.resolve(strict=True) if ns.binary else find_default_binary(), ns.duration)
