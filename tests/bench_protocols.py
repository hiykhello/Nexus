#!/usr/bin/env python3
"""Batch 158 full-protocol loopback throughput & RSS stability benchmark harness."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def find_nexus_bin(cli_arg: str | None) -> pathlib.Path:
    for p in [cli_arg, os.environ.get("NEXUS_BIN")]:
        if p and pathlib.Path(p).is_file():
            return pathlib.Path(p)
    for cand in sorted((ROOT / "target").glob("*/*/bin/nexus")):
        if cand.is_file():
            return cand
    raise FileNotFoundError("nexus binary not found; pass --nexus <path>")


def read_rss_mib_and_fds(pid: int) -> tuple[float, int]:
    status = pathlib.Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    rss_kib = 0.0
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            rss_kib = float(line.split()[1])
            break
    fd_count = len(list(pathlib.Path(f"/proc/{pid}/fd").iterdir()))
    return rss_kib / 1024.0, fd_count


class EchoServer:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop_ev = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _serve(self, c: socket.socket) -> None:
        with c:
            while data := c.recv(65536):
                c.sendall(data)

    def _run(self) -> None:
        while not self.stop_ev.is_set():
            try:
                conn, _ = self.sock.accept()
                threading.Thread(target=self._serve, args=(conn,), daemon=True).start()
            except TimeoutError:
                continue
            except OSError:
                break

    def close(self) -> None:
        self.stop_ev.set()
        self.sock.close()


def socks5_transfer(proxy_port: int, dst_port: int, payload: bytes) -> float:
    t0 = time.perf_counter()
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as s:
        s.sendall(b"\x05\x01\x00")
        assert s.recv(2) == b"\x05\x00"
        req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + dst_port.to_bytes(2, "big")
        s.sendall(req)
        rep = s.recv(10)
        assert len(rep) >= 4 and rep[1] == 0
        lat_ms = (time.perf_counter() - t0) * 1000.0
        s.sendall(payload)
        got = 0
        view = memoryview(payload)
        while got < len(payload):
            chunk = s.recv(65536)
            assert chunk, "unexpected EOF"
            assert chunk == view[got : got + len(chunk)].tobytes(), "payload corruption"
            got += len(chunk)
    return lat_ms


def http_connect_transfer(proxy_port: int, dst_port: int, payload: bytes) -> float:
    t0 = time.perf_counter()
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as s:
        s.sendall(f"CONNECT 127.0.0.1:{dst_port} HTTP/1.1\r\nHost: 127.0.0.1:{dst_port}\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(1024)
            assert c
            buf += c
        assert b"200" in buf.split(b"\r\n", 1)[0]
        lat_ms = (time.perf_counter() - t0) * 1000.0
        s.sendall(payload)
        got = 0
        view = memoryview(payload)
        while got < len(payload):
            chunk = s.recv(65536)
            assert chunk
            assert chunk == view[got : got + len(chunk)].tobytes()
            got += len(chunk)
    return lat_ms


def wait_port(port: int, proc: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            o, e = proc.communicate()
            raise RuntimeError(f"nexus exited early rc={proc.returncode}\n{o}\n{e}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"timeout waiting for 127.0.0.1:{port}")


def run_benchmark(nexus: pathlib.Path, payload_mib: int, iterations: int) -> dict[str, object]:
    echo = EchoServer()
    s5_port, http_port, mix_port = free_port(), free_port(), free_port()
    payload = os.urandom(payload_mib * 1024 * 1024)
    results: list[dict[str, object]] = []
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-bench-") as td:
            cfg = pathlib.Path(td) / "bench.kdl"
            cfg.write_text(
                f'schema-version 1\nrole "client"\n'
                f'inbound "s5" type="socks5" {{ listen host="127.0.0.1" port={s5_port}; authentication "none"; }}\n'
                f'inbound "hc" type="http" {{ listen host="127.0.0.1" port={http_port}; authentication "none"; }}\n'
                f'inbound "mx" type="mixed" {{ listen host="127.0.0.1" port={mix_port}; authentication "none"; }}\n'
                f'outbound "direct" type="direct"\n'
                f'routing {{ final "direct"; }}\n',
                encoding="utf-8",
            )
            proc = subprocess.Popen(
                [str(nexus), "run", "--config", str(cfg)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                wait_port(mix_port, proc)
                rss_start, fds_start = read_rss_mib_and_fds(proc.pid)
                cases = [
                    ("socks5-direct", lambda: socks5_transfer(s5_port, echo.port, payload)),
                    ("http-connect-direct", lambda: http_connect_transfer(http_port, echo.port, payload)),
                    ("mixed-socks5-direct", lambda: socks5_transfer(mix_port, echo.port, payload)),
                ]
                for name, fn in cases:
                    lats = []
                    t_begin = time.perf_counter()
                    for _ in range(iterations):
                        lats.append(fn())
                    elapsed = time.perf_counter() - t_begin
                    mbps = (len(payload) * iterations * 2 * 8) / elapsed / 1_000_000.0
                    lats_sorted = sorted(lats)
                    p95 = lats_sorted[min(len(lats_sorted) - 1, int(len(lats_sorted) * 0.95))]
                    results.append({
                        "protocol": name,
                        "payload_mib": payload_mib,
                        "iterations": iterations,
                        "throughput_mbps": round(mbps, 2),
                        "p50_connect_ms": round(statistics.median(lats_sorted), 3),
                        "p95_connect_ms": round(p95, 3),
                    })
                time.sleep(0.1)
                rss_end, fds_end = read_rss_mib_and_fds(proc.pid)
            finally:
                proc.terminate()
                proc.wait(timeout=5)
    finally:
        echo.close()

    fd_delta = fds_end - fds_start
    assert rss_end <= 96.0, f"RSS budget exceeded: {rss_end:.2f} MiB > 96 MiB"
    assert fd_delta <= 8, f"FD leak detected: delta={fd_delta}"
    return {
        "rss_start_mib": round(rss_start, 2),
        "rss_end_mib": round(rss_end, 2),
        "fds_start": fds_start,
        "fds_end": fds_end,
        "fd_delta": fd_delta,
        "benchmarks": results,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--nexus", default=None)
    ap.add_argument("--quick", action="store_true", help="run fast 2 MiB x 2 iterations per case")
    ap.add_argument("--payload-mib", type=int, default=8)
    ap.add_argument("--iterations", type=int, default=3)
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()
    mib = 2 if args.quick else args.payload_mib
    iters = 2 if args.quick else args.iterations
    report = run_benchmark(find_nexus_bin(args.nexus), mib, iters)
    text = json.dumps(report, indent=2)
    if args.json_out:
        pathlib.Path(args.json_out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
