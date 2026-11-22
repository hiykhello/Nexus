#!/usr/bin/env python3
"""Batch 131: High-concurrency storm + live reload/network-change/close-all + FD/RSS zero-leak stress."""
import argparse
import concurrent.futures
import hashlib
import json
import os
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

from detour_network import exact, reserve, socks
from dns_rule_support import udp_client


def start_tcp_echo():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(256)
    stop = threading.Event()

    def handle(c):
        try:
            c.settimeout(10)
            while d := c.recv(32768):
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
            except TimeoutError:
                continue
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1], stop


def start_udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    stop = threading.Event()

    def serve():
        s.settimeout(0.2)
        while not stop.is_set():
            try:
                d, a = s.recvfrom(65535)
                s.sendto(d, a)
            except TimeoutError:
                continue
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return s, s.getsockname()[1], stop


def http_req(port: int, method: str, path: str, body: bytes | None = None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, r.read().decode("utf-8", errors="replace")


def proc_stats(pid: int):
    fds = len(os.listdir(f"/proc/{pid}/fd"))
    rss_kb = 0
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            rss_kb = int(line.split()[1])
    return fds, rss_kb / 1024.0


def test_suite(binary: Path):
    tsrv, tport, tstop = start_tcp_echo()
    u1, up1, ustop1 = start_udp_echo()
    u2, up2, ustop2 = start_udp_echo()
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-b131-") as d:
            root = Path(d)
            front, ctrl = reserve(), reserve()
            while ctrl == front:
                ctrl = reserve()
            rules = root / "rules.kdl"
            rules.write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="blocked1.test"\n')
            cfg = root / "stress.kdl"
            cfg.write_text(f'''schema-version 1
role "client"
workers 2
tcp-splice-pipes 16
control http-listen="127.0.0.1:{ctrl}" metrics=#true
inbound "mixed" type="mixed" {{
    listen host="127.0.0.1" port={front}
    authentication "none"
}}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{
    rule-set "dyn" path="{rules}" format="kdl"
    rule kind="rule-set" value="dyn" outbound="reject"
    default-outbound "direct"
}}
''')
            proc = subprocess.Popen([str(binary), "run", "--config", str(cfg)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                started = False
                for _ in range(100):
                    if proc.poll() is not None:
                        raise RuntimeError(f"nexus exited early ({proc.returncode}): {proc.stderr.read().decode(errors='replace')}")
                    try:
                        with socket.create_connection(("127.0.0.1", front), timeout=0.2):
                            started = True
                            break
                    except OSError:
                        time.sleep(0.02)
                assert started, "nexus did not start listening"

                # Warmup 4 connections to populate worker pools before recording baseline
                for _ in range(4):
                    with socks(front, 1, ("127.0.0.1", tport))[0] as s:
                        s.sendall(b"warmup")
                        assert exact(s, 6) == b"warmup"
                time.sleep(0.15)
                base_fds, base_rss = proc_stats(proc.pid)

                # 1. Storm: 96 concurrent TCP streams (32 KiB each) + 24 multi-target UDP NAT + live control ops!
                def tcp_worker(idx):
                    blob = os.urandom(32768)
                    with socks(front, 1, ("127.0.0.1", tport))[0] as s:
                        s.settimeout(12)
                        s.sendall(blob)
                        assert hashlib.sha256(exact(s, len(blob))).digest() == hashlib.sha256(blob).digest()

                def udp_worker(idx):
                    with udp_client(front) as (u, relay):
                        u.settimeout(5)
                        for p in (up1, up2):
                            msg = f"u-{idx}-{p}-".encode() + os.urandom(16)
                            pkt = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", p) + msg
                            u.sendto(pkt, relay)
                            assert u.recv(4096) == pkt

                def control_worker():
                    for step in range(4):
                        rules.write_text(f'schema-version 2\nkind "predicate"\nrule type="domain" value="blocked{step + 2}.test"\n')
                        st, _ = http_req(ctrl, "POST", "/v1/reload", b"{}")
                        assert st in (200, 202), st
                        st, _ = http_req(ctrl, "POST", "/v1/network-change", b"{}")
                        assert st in (200, 202), st
                        st, _ = http_req(ctrl, "POST", "/v1/state/clear-cache", b'{"target":"all"}')
                        assert st in (200, 202), st
                        st, diag = http_req(ctrl, "GET", "/v1/diagnostics")
                        assert st == 200 and "active_connections" in diag, (st, diag)
                        st, metrics = http_req(ctrl, "GET", "/metrics")
                        assert st == 200 and "nexus_" in metrics, st
                        time.sleep(0.03)

                with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
                    futs = [pool.submit(control_worker)]
                    futs += [pool.submit(tcp_worker, i) for i in range(96)]
                    futs += [pool.submit(udp_worker, i) for i in range(24)]
                    for f in futs:
                        f.result()

                # 2. Open 16 idle sessions, trigger DELETE /v1/connections (close-all), verify all get EOF!
                idle = [socks(front, 1, ("127.0.0.1", tport))[0] for _ in range(16)]
                try:
                    for s in idle:
                        s.settimeout(3)
                        s.sendall(b"ping")
                        assert exact(s, 4) == b"ping"
                    st, body = http_req(ctrl, "DELETE", "/v1/connections")
                    assert st == 200, (st, body)
                    for s in idle:
                        try:
                            assert s.recv(16) == b""
                        except ConnectionResetError:
                            pass
                finally:
                    for s in idle:
                        s.close()

                # 3. Wait briefly for cleanup and assert ZERO FD leak & bounded RSS!
                time.sleep(0.35)
                end_fds, end_rss = proc_stats(proc.pid)
                fd_delta = end_fds - base_fds
                assert fd_delta <= 4, f"FD leak detected! base={base_fds} end={end_fds} delta={fd_delta}"
                assert end_rss < 40.0, f"RSS exceeded 40 MiB budget! base={base_rss:.2f} end={end_rss:.2f} MiB"

                # 4. Final post-storm health check
                with socks(front, 1, ("127.0.0.1", tport))[0] as s:
                    s.sendall(b"healthy-after-storm")
                    assert exact(s, 19) == b"healthy-after-storm"

                print(
                    f"BATCH 131 CONCURRENCY/RELOAD/LEAK STRESS PASSED [{binary.name}]: "
                    f"FDs {base_fds}->{end_fds} (delta={fd_delta}), VmRSS {base_rss:.2f}->{end_rss:.2f} MiB",
                    flush=True,
                )
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
    finally:
        tstop.set(); tsrv.close()
        ustop1.set(); u1.close()
        ustop2.set(); u2.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("binary", type=Path)
    test_suite(p.parse_args().binary.resolve(strict=True))
