#!/usr/bin/env python3
"""Cross-implementation loopback SOCKS5 benchmark harness (Nexus vs official vp_core Release)."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import socket
import statistics
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
from typing import Callable

ROOT = pathlib.Path(__file__).resolve().parent.parent
MIB = 1024 * 1024
CLK_TCK = os.sysconf("SC_CLK_TCK")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"unexpected EOF after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def read_rss_mib_and_fds(pid: int) -> tuple[float, int]:
    rss_kib = 0.0
    for line in pathlib.Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            rss_kib = float(line.split()[1])
            break
    fds = len(list(pathlib.Path(f"/proc/{pid}/fd").iterdir()))
    return rss_kib / 1024.0, fds


def read_proc_cpu_s(pid: int) -> float:
    stat = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    after = stat[stat.rfind(")") + 2:].split()
    utime = int(after[11])
    stime = int(after[12])
    return (utime + stime) / float(CLK_TCK)


def latest_bin(pattern_dir: pathlib.Path) -> str:
    candidates = sorted(
        pattern_dir.glob("*/bin/nexus"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0.0,
        reverse=True,
    )
    return str(candidates[0]) if candidates else ""


def ensure_official_vpcore(dest: pathlib.Path, tag: str, fetch: bool) -> pathlib.Path:
    if dest.is_file():
        return dest
    if not fetch:
        raise FileNotFoundError(f"vp_core binary not found: {dest} (pass --fetch-vpcore to download {tag})")
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/mateo-ki/vp_core/releases/download/{tag}/vpcore-{tag}-x86_64-unknown-linux-musl.tar.gz"
    with tempfile.TemporaryDirectory(prefix="vpcore-fetch-", dir=dest.parent) as td:
        archive = pathlib.Path(td) / "vpcore.tar.gz"
        print(f"Fetching official vp_core {tag}: {url}", file=sys.stderr, flush=True)
        urllib.request.urlretrieve(url, archive)
        with tarfile.open(archive, "r:gz") as tf:
            member = next((m for m in tf.getmembers() if m.isfile() and pathlib.Path(m.name).name == "vpcore"), None)
            if member is None:
                raise RuntimeError(f"vpcore executable not found inside {url}")
            extracted = tf.extractfile(member)
            assert extracted is not None
            tmp_bin = pathlib.Path(td) / "vpcore"
            tmp_bin.write_bytes(extracted.read())
            tmp_bin.chmod(0o755)
            tmp_bin.replace(dest)
    return dest


class BenchOrigin:
    """Fast threaded TCP echo ('E') and byte-counting sink ('S') loopback target."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(256)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop_ev = threading.Event()
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(30.0)
            try:
                mode = conn.recv(1)
                if not mode:
                    return
                if mode == b"E":
                    while data := conn.recv(65536):
                        conn.sendall(data)
                elif mode == b"S":
                    expected = struct.unpack("!Q", recv_exact(conn, 8))[0]
                    received = 0
                    scratch = bytearray(262144)
                    mv = memoryview(scratch)
                    while received < expected:
                        to_read = min(len(scratch), expected - received)
                        n = conn.recv_into(mv[:to_read])
                        if n <= 0:
                            raise RuntimeError(f"sink truncated at {received}/{expected}")
                        received += n
                    conn.sendall(struct.pack("!Q", received))
            except OSError:
                pass

    def _accept_loop(self) -> None:
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
        self.thread.join(timeout=2.0)


def socks5_connect(proxy_port: int, dst_port: int, timeout: float = 15.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.connect(("127.0.0.1", proxy_port))
        s.sendall(b"\x05\x01\x00")
        if recv_exact(s, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 greeting rejected")
        req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + dst_port.to_bytes(2, "big")
        s.sendall(req)
        hdr = recv_exact(s, 4)
        if hdr[1] != 0:
            raise RuntimeError(f"SOCKS5 connect failed code={hdr[1]}")
        if hdr[3] == 1:
            recv_exact(s, 6)
        elif hdr[3] == 4:
            recv_exact(s, 18)
        elif hdr[3] == 3:
            alen = recv_exact(s, 1)[0]
            recv_exact(s, alen + 2)
        return s
    except Exception:
        s.close()
        raise


def socks5_echo(proxy_port: int, origin_port: int, payload: bytes) -> float:
    t0 = time.perf_counter()
    with socks5_connect(proxy_port, origin_port) as s:
        s.sendall(b"E" + payload)
        if recv_exact(s, len(payload)) != payload:
            raise RuntimeError("echo mismatch")
    return (time.perf_counter() - t0) * 1000.0


def socks5_sink_push(proxy_port: int, origin_port: int, total_bytes: int, chunk: bytes) -> None:
    with socks5_connect(proxy_port, origin_port, timeout=60.0) as s:
        s.sendall(b"S" + struct.pack("!Q", total_bytes))
        rem = total_bytes
        mv = memoryview(chunk)
        while rem > 0:
            n = min(len(chunk), rem)
            s.sendall(mv[:n])
            rem -= n
        ack = struct.unpack("!Q", recv_exact(s, 8))[0]
        if ack != total_bytes:
            raise RuntimeError(f"sink ACK mismatch: {ack} != {total_bytes}")


def wait_tcp_listen(proc: subprocess.Popen[str], proxy_port: int, label: str, t0: float) -> float:
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate()
            raise RuntimeError(f"{label} exited rc={proc.returncode}\n{out}\n{err}")
        try:
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.05):
                return (time.perf_counter() - t0) * 1000.0
        except OSError:
            time.sleep(0.0001)
    raise RuntimeError(f"{label} tcp listen timed out on port {proxy_port}")


def wait_ready_echo(proc: subprocess.Popen[str], proxy_port: int, origin_port: int, label: str, t0: float) -> float:
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate()
            raise RuntimeError(f"{label} exited rc={proc.returncode}\n{out}\n{err}")
        try:
            socks5_echo(proxy_port, origin_port, b"ping-nexus-bench")
            return (time.perf_counter() - t0) * 1000.0
        except (OSError, RuntimeError):
            time.sleep(0.0001)
    raise RuntimeError(f"{label} readiness timed out on port {proxy_port}")


def stop_proc(proc: subprocess.Popen[str]) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def write_nexus_cfg(path: pathlib.Path, port: int) -> None:
    path.write_text(
        f'schema-version 1\nrole "client"\nworkers 1\n'
        f'inbound "s5" type="socks5" {{\n    listen host="127.0.0.1" port={port}\n    authentication "none"\n}}\n'
        f'outbound "direct" type="direct"\nrouting {{\n    default-outbound "direct"\n}}\n',
        encoding="utf-8",
    )


def write_vp_cfg(path: pathlib.Path, port: int) -> None:
    path.write_text(
        f"socks-port: {port}\nbind-address: 127.0.0.1\nmode: direct\nlog-level: error\nallow-lan: false\ndns:\n  enable: false\ntun:\n  enable: false\n",
        encoding="utf-8",
    )


def bench_engine(
    label: str,
    binary: pathlib.Path,
    make_cmd_env: Callable[[pathlib.Path, int], tuple[list[str], dict[str, str]]],
    origin: BenchOrigin,
    bulk_chunk: bytes,
    single_mib: int,
    multi_streams: int,
    multi_each_mib: int,
    rpc_count: int,
) -> dict[str, object]:
    listen_runs: list[float] = []
    echo_runs: list[float] = []
    with tempfile.TemporaryDirectory(prefix="bench-cmp-") as td:
        tmp = pathlib.Path(td)
        for i in range(5):
            p = free_port()
            cmd, env_extra = make_cmd_env(tmp / f"listen_{i}", p)
            env = {**os.environ, **env_extra}
            t0 = time.perf_counter()
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
            try:
                listen_runs.append(wait_tcp_listen(proc, p, label, t0))
            finally:
                stop_proc(proc)

        for i in range(2):
            p = free_port()
            cmd, env_extra = make_cmd_env(tmp / f"cold_{i}", p)
            env = {**os.environ, **env_extra}
            t0 = time.perf_counter()
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
            try:
                echo_runs.append(wait_ready_echo(proc, p, origin.port, label, t0))
            finally:
                stop_proc(proc)

        port = free_port()
        cmd, env_extra = make_cmd_env(tmp / "main", port)
        env = {**os.environ, **env_extra}
        t0 = time.perf_counter()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        try:
            echo_runs.append(wait_ready_echo(proc, port, origin.port, label, t0))
            time.sleep(0.05)
            rss_idle_mib, fds_idle = read_rss_mib_and_fds(proc.pid)

            socks5_sink_push(port, origin.port, 16 * MIB, bulk_chunk)

            s1_speeds: list[float] = []
            s1_cpus: list[float] = []
            for _ in range(3):
                cpu0 = read_proc_cpu_s(proc.pid)
                t1 = time.perf_counter()
                socks5_sink_push(port, origin.port, single_mib * MIB, bulk_chunk)
                single_s = time.perf_counter() - t1
                cpu1 = read_proc_cpu_s(proc.pid)
                s1_speeds.append(single_mib / single_s)
                s1_cpus.append(((cpu1 - cpu0) * 1e9) / float(single_mib * MIB))
            single_mib_s = statistics.median(s1_speeds)
            s1_cpu_ns_b = statistics.median(s1_cpus)

            barrier = threading.Barrier(multi_streams + 1)

            def worker() -> None:
                barrier.wait()
                socks5_sink_push(port, origin.port, multi_each_mib * MIB, bulk_chunk)

            with concurrent.futures.ThreadPoolExecutor(max_workers=multi_streams) as pool:
                futs = [pool.submit(worker) for _ in range(multi_streams)]
                barrier.wait()
                cpu2 = read_proc_cpu_s(proc.pid)
                t2 = time.perf_counter()
                for f in futs:
                    f.result()
                multi_s = time.perf_counter() - t2
                cpu3 = read_proc_cpu_s(proc.pid)
            multi_total_mib = multi_streams * multi_each_mib
            multi_mib_s = multi_total_mib / multi_s
            m16_cpu_ns_b = ((cpu3 - cpu2) * 1e9) / float(multi_total_mib * MIB)

            rpc_payload = b"x" * 64
            rtts: list[float] = []
            t3 = time.perf_counter()
            for _ in range(rpc_count):
                rtts.append(socks5_echo(port, origin.port, rpc_payload))
            rpc_s = time.perf_counter() - t3
            rtts.sort()
            p50 = statistics.median(rtts)
            p95 = rtts[min(len(rtts) - 1, int(len(rtts) * 0.95))]
            p99 = rtts[min(len(rtts) - 1, int(len(rtts) * 0.99))]

            rss_load_mib, fds_load = read_rss_mib_and_fds(proc.pid)
            time.sleep(0.7)
            rss_reap_mib, fds_reap = read_rss_mib_and_fds(proc.pid)
        finally:
            stop_proc(proc)

    size_mib = binary.stat().st_size / float(MIB)
    return {
        "engine": label,
        "binary": str(binary),
        "bin_mib": round(size_mib, 2),
        "listen_ms": round(statistics.median(listen_runs), 2),
        "echo_ms": round(statistics.median(echo_runs), 2),
        "single_mib_s": round(single_mib_s, 1),
        "s1_cpu_ns_b": round(s1_cpu_ns_b, 3),
        "multi16_mib_s": round(multi_mib_s, 1),
        "m16_cpu_ns_b": round(m16_cpu_ns_b, 3),
        "rpc_rps": round(rpc_count / rpc_s, 1),
        "rpc_p50_ms": round(p50, 3),
        "rpc_p95_ms": round(p95, 3),
        "rpc_p99_ms": round(p99, 3),
        "rss_idle_mib": round(rss_idle_mib, 2),
        "rss_load_mib": round(rss_load_mib, 2),
        "rss_reap_mib": round(rss_reap_mib, 2),
        "fds_idle": fds_idle,
        "fds_load": fds_load,
        "fds_reap": fds_reap,
        "fds": f"{fds_idle}->{fds_load}->{fds_reap}",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nexus-epoll", default=latest_bin(ROOT / "mcpp/epoll/target/x86_64-linux-gnu"))
    ap.add_argument("--nexus-uring", default=latest_bin(ROOT / "target/x86_64-linux-gnu"))
    ap.add_argument("--nexus-uring-size", default="")
    ap.add_argument("--vpcore-tag", default="v1.7.9")
    ap.add_argument("--vpcore", default=None)
    ap.add_argument("--fetch-vpcore", action="store_true")
    ap.add_argument("--single-mib", type=int, default=1024)
    ap.add_argument("--multi-each-mib", type=int, default=32)
    ap.add_argument("--multi-streams", type=int, default=16)
    ap.add_argument("--rpc-count", type=int, default=400)
    args = ap.parse_args()

    if not args.nexus_epoll or not args.nexus_uring:
        raise FileNotFoundError("could not auto-discover nexus epoll/uring binaries; pass --nexus-epoll and --nexus-uring")

    vpcore_default = pathlib.Path(f"/tmp/nexus-bench-cache/vpcore-{args.vpcore_tag}-musl/vpcore")
    vpcore_bin = pathlib.Path(args.vpcore) if args.vpcore else ensure_official_vpcore(vpcore_default, args.vpcore_tag, args.fetch_vpcore)

    engines: list[tuple[str, pathlib.Path, str]] = [
        ("Nexus (epoll, 1w)", pathlib.Path(args.nexus_epoll), "nexus"),
        ("Nexus (io_uring, 1w)", pathlib.Path(args.nexus_uring), "nexus"),
    ]
    if args.nexus_uring_size:
        engines.append(("Nexus (io_uring, size, 1w)", pathlib.Path(args.nexus_uring_size), "nexus"))
    vp_label = f"vp_core {args.vpcore_tag} official (musl, 1w)" if not args.vpcore else f"vp_core {args.vpcore_tag} (1w)"
    engines.append((vp_label, vpcore_bin, "vpcore"))

    for label, p, _ in engines:
        if not p.is_file():
            raise FileNotFoundError(f"{label} binary not found: {p}")

    def nexus_cmd_env(binary: pathlib.Path, cfg_dir: pathlib.Path, port: int) -> tuple[list[str], dict[str, str]]:
        cfg = cfg_dir.with_suffix(".kdl")
        write_nexus_cfg(cfg, port)
        return [str(binary), "run", "--config", str(cfg)], {}

    def vp_cmd_env(binary: pathlib.Path, cfg_dir: pathlib.Path, port: int) -> tuple[list[str], dict[str, str]]:
        cfg = cfg_dir.with_suffix(".yaml")
        write_vp_cfg(cfg, port)
        return [str(binary), "run", "-c", str(cfg), "-l", "error"], {"TOKIO_WORKER_THREADS": "1"}

    bulk_chunk = os.urandom(262144)
    origin = BenchOrigin()
    rows: list[dict[str, object]] = []
    try:
        for label, binary, kind in engines:
            maker = nexus_cmd_env if kind == "nexus" else vp_cmd_env
            rows.append(bench_engine(
                label, binary,
                lambda d, p, b=binary, m=maker: m(b, d, p),
                origin, bulk_chunk, args.single_mib, args.multi_streams, args.multi_each_mib, args.rpc_count,
            ))
    finally:
        origin.close()

    hdr = (
        "| Engine | Bin(MiB) | Listen(ms) | Echo(ms) | 1-Stream(MiB/s) | 1S-CPU(ns/B) | "
        "16-Stream(MiB/s) | 16S-CPU(ns/B) | 400-RPC(RPS) | p50/p95/p99(ms) | RSS(Idle->Load) | FDs(idle->load->reap) |"
    )
    sep = "|" + "|".join(["---"] * 12) + "|"
    print(hdr)
    print(sep)
    for r in rows:
        print(
            f"| {r['engine']} | {r['bin_mib']} | {r['listen_ms']} | {r['echo_ms']} | "
            f"{r['single_mib_s']} | {r['s1_cpu_ns_b']} | {r['multi16_mib_s']} | {r['m16_cpu_ns_b']} | "
            f"{r['rpc_rps']} | {r['rpc_p50_ms']}/{r['rpc_p95_ms']}/{r['rpc_p99_ms']} | "
            f"{r['rss_idle_mib']}->{r['rss_load_mib']} | {r['fds']} |"
        )
    print("\nJSON:", json.dumps(rows, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
