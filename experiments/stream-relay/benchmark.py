#!/usr/bin/env python3
"""Interleaved loopback comparison of TCP relay binaries; retain every sample."""
import argparse
import base64
import datetime
import hashlib
import json
import os
import pathlib
import platform
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time

REVISION = "824dbcfb4dd0a95921840b1737b950cde590241e"
UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"
METHOD = "2022-blake3-aes-128-gcm"
PASSWORD = base64.b64encode(bytes(range(16))).decode()
CHUNK = bytes(range(256)) * 256


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while part := source.read(1024 * 1024):
            digest.update(part)
    return digest.hexdigest()


def free_ports(count):
    # SS binds TCP and UDP on the same port. Reserve both outside Linux's
    # ephemeral range so other sockets opened during startup cannot take UDP.
    first_ephemeral = int(pathlib.Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()[0])
    candidates = list(range(1024, first_ephemeral))
    random.SystemRandom().shuffle(candidates)
    sockets = []
    ports = []
    try:
        for port in candidates:
            tcp = socket.socket()
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                tcp.bind(("127.0.0.1", port)); udp.bind(("127.0.0.1", port))
            except OSError:
                tcp.close(); udp.close(); continue
            sockets.extend((tcp, udp)); ports.append(port)
            if len(ports) == count:
                return ports
        raise RuntimeError("unable to reserve TCP and UDP ports")
    finally:
        for sock in sockets:
            sock.close()


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError(f"unexpected EOF after {len(data)} of {size} bytes")
        data.extend(part)
    return bytes(data)


def ready(port, processes):
    deadline = time.monotonic() + 10
    while True:
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f"{process.args!r} exited {process.returncode}")
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=1)
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.02)


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait()
        raise RuntimeError(f"{process.args!r} did not stop")


def cpu_ticks(pid):
    fields = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[11]) + int(fields[12])


def peak_rss_kib(pid):
    for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1])
    raise RuntimeError("missing VmHWM")


def inbound_config(kind, port, root):
    if kind == "ss":
        return f'inbound "edge" type="shadowsocks" {{ listen host="127.0.0.1" port={port}; method "{METHOD}"; key-file "{root / "ss-key"}"; }}'
    if kind == "vless":
        return f'inbound "edge" type="vless" {{ listen host="127.0.0.1" port={port}; authentication {{ user "test" uuid-file="{root / "uuid"}"; }}; tls {{ certificate-file "{root / "cert"}"; private-key-file "{root / "key"}"; }}; }}'
    return f'inbound "edge" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}'


def outbound_config(kind, port, root):
    if kind == "ss":
        return f'outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={port}; method "{METHOD}"; key-file "{root / "ss-key"}"; }}'
    return f'outbound "edge" type="vless" {{ server host="127.0.0.1" port={port}; authentication {{ uuid-file "{root / "uuid"}"; }}; tls {{ server-name "localhost"; ca-file "{root / "cert"}"; verify #true; }}; }}'


def box_outbound(kind, port, root):
    if kind == "ss":
        return {"type": "shadowsocks", "server": "127.0.0.1", "server_port": port,
                "method": METHOD, "password": PASSWORD}
    return {"type": "vless", "server": "127.0.0.1", "server_port": port, "uuid": UUID,
            "tls": {"enabled": True, "server_name": "localhost", "certificate_path": str(root / "cert")}}


def socks_connect(port, target, processes):
    client = ready(port, processes)
    client.settimeout(30)
    try:
        client.sendall(b"\x05\x01\x00")
        if exact(client, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS greeting failed")
        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target.to_bytes(2, "big"))
        head = exact(client, 4)
        if head[:2] != b"\x05\x00":
            raise RuntimeError(f"SOCKS connect failed: {head!r}")
        exact(client, 6 if head[3] == 1 else 18)
        return client
    except BaseException:
        client.close()
        raise


def transfer(client, peer, size, process):
    peer.settimeout(30)
    client.sendall(b"ready")
    if exact(peer, 5) != b"ready":
        raise RuntimeError("wrong preface")
    peer.sendall(b"ready")
    if exact(client, 5) != b"ready":
        raise RuntimeError("wrong preface reply")
    expected = hashlib.sha256()
    for _ in range(size // len(CHUNK)):
        expected.update(CHUNK)
    expected = expected.digest()
    errors = []
    origin_hash = hashlib.sha256()
    def echo():
        try:
            buf = bytearray(len(CHUNK)); remaining = size
            while remaining:
                count = peer.recv_into(buf, min(len(buf), remaining))
                if not count:
                    raise RuntimeError("truncated upload")
                part = memoryview(buf)[:count]
                origin_hash.update(part); peer.sendall(part); remaining -= count
            peer.shutdown(socket.SHUT_WR)
        except Exception as exc:
            errors.append(f"origin: {exc!r}")
    def send():
        try:
            for _ in range(size // len(CHUNK)):
                client.sendall(CHUNK)
        except Exception as exc:
            errors.append(f"sender: {exc!r}")
    origin = threading.Thread(target=echo, daemon=True)
    sender = threading.Thread(target=send, daemon=True)
    before = cpu_ticks(process.pid)
    started = time.monotonic_ns()
    origin.start(); sender.start()
    received = hashlib.sha256(); buf = bytearray(len(CHUNK)); remaining = size
    while remaining:
        count = client.recv_into(buf, min(len(buf), remaining))
        if not count:
            raise RuntimeError("truncated download")
        received.update(memoryview(buf)[:count]); remaining -= count
    elapsed = time.monotonic_ns() - started
    after = cpu_ticks(process.pid)
    sender.join(30); origin.join(30)
    if sender.is_alive() or origin.is_alive() or errors:
        raise RuntimeError(f"relay tasks failed: {errors!r}")
    if received.digest() != expected or origin_hash.digest() != expected:
        raise RuntimeError("relay payload digest mismatch")
    return {"elapsed_ns": elapsed, "bytes_each_direction": size,
            "proxy_cpu_ticks": after - before, "proxy_peak_rss_kib": peak_rss_kib(process.pid)}


def sample(binary, mode, size, proxy_cpu, peer_cpus, root, errors_file):
    front, socks, upstream_port = free_ports(3)
    parts = mode.split("-")
    incoming = parts[0]
    outgoing = parts[1] if len(parts) > 1 else "direct"
    edge = outbound_config(outgoing, upstream_port, root) if outgoing != "direct" else ""
    (root / "nexus.kdl").write_text(f'''schema-version 1
role "server"
workers 1
{inbound_config(incoming, front, root)}
outbound "direct" type="direct"
{edge}
routing {{ default-outbound "{'edge' if edge else 'direct'}"; }}
''')
    processes = []
    proxy = None
    try:
        if edge:
            upstream_inbound = ({"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": upstream_port,
                                 "method": METHOD, "password": PASSWORD} if outgoing == "ss" else
                                {"type": "vless", "listen": "127.0.0.1", "listen_port": upstream_port,
                                 "users": [{"uuid": UUID}], "tls": {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")}})
            (root / "upstream.json").write_text(json.dumps({"log": {"level": "error"}, "inbounds": [upstream_inbound], "outbounds": [{"type": "direct"}]}))
            upstream = subprocess.Popen(["taskset", "-c", peer_cpus, "sing-box", "run", "-c", root / "upstream.json"], stdout=subprocess.DEVNULL, stderr=errors_file)
            processes.append(upstream)
            with ready(upstream_port, processes):
                pass
        proxy = subprocess.Popen(["taskset", "-c", str(proxy_cpu), binary, "run", "--config", root / "nexus.kdl"], stdout=subprocess.DEVNULL, stderr=errors_file)
        processes.append(proxy)
        with ready(front, processes):
            pass
        if os.sched_getaffinity(proxy.pid) != {proxy_cpu}:
            raise RuntimeError("proxy CPU affinity not applied")
        if incoming != "direct":
            config = {"log": {"level": "error"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks}],
                      "outbounds": [box_outbound(incoming, front, root)]}
            (root / "client.json").write_text(json.dumps(config))
            box = subprocess.Popen(["taskset", "-c", peer_cpus, "sing-box", "run", "-c", root / "client.json"], stdout=subprocess.DEVNULL, stderr=errors_file)
            processes.append(box)
        else:
            socks = front
        with socket.socket() as origin:
            origin.bind(("127.0.0.1", 0)); origin.listen(2); origin.settimeout(30)
            with socks_connect(socks, origin.getsockname()[1], processes) as client:
                client.sendall(b"ready")
                with origin.accept()[0] as peer:
                    # The first preface caused delayed protocol handshakes to dial.
                    peer.settimeout(30)
                    if exact(peer, 5) != b"ready":
                        raise RuntimeError("wrong initial preface")
                    return transfer(client, peer, size, proxy)
    finally:
        for process in reversed(processes):
            stop(process)
        if proxy and proxy.returncode:
            raise RuntimeError(f"proxy exited {proxy.returncode}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=pathlib.Path)
    parser.add_argument("candidate", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--mode", choices=("direct", "ss-direct", "vless-direct", "ss-ss", "vless-vless"), required=True)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--mib", type=int, default=64)
    parser.add_argument("--proxy-cpu", type=int, required=True)
    parser.add_argument("--peer-cpus", required=True, help="taskset CPU list for this driver and sing-box")
    parser.add_argument("--baseline-tree", type=pathlib.Path, required=True)
    parser.add_argument("--candidate-tree", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.rounds < 1 or args.mib < 1:
        parser.error("rounds and MiB must be positive")
    args.baseline = args.baseline.resolve(); args.candidate = args.candidate.resolve()
    allowed = os.sched_getaffinity(0)
    peers = set()
    for part in args.peer_cpus.split(","):
        low, *high = part.split("-")
        peers.update(range(int(low), int(high[0]) + 1) if high else (int(low),))
    if args.proxy_cpu not in allowed or not peers or not peers <= allowed or args.proxy_cpu in peers:
        parser.error("CPUs must be allowed and the proxy CPU must be separate from peers")
    os.sched_setaffinity(0, peers)
    version = subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout
    if f"Revision: {REVISION}" not in version:
        raise RuntimeError("unexpected sing-box revision")
    cpu_model = next((line.split(":", 1)[1].strip() for line in pathlib.Path("/proc/cpuinfo").read_text().splitlines()
                      if line.startswith("model name")), "unknown")
    governor = pathlib.Path(f"/sys/devices/system/cpu/cpu{args.proxy_cpu}/cpufreq/scaling_governor")
    paths = ("src/net/stream_relay.cppm", "src/proxy/stream_relay.cppm", "mcpp.toml", "mcpp.lock")
    source_hashes = {name: {path: sha256(tree / path) for path in paths}
                     for name, tree in (("baseline", args.baseline_tree), ("candidate", args.candidate_tree))}
    metadata = {"kind": "environment", "mode": args.mode, "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "kernel": platform.release(), "machine": platform.machine(),
                "cpu": cpu_model, "governor": governor.read_text().strip() if governor.exists() else "unknown",
                "loopback_mtu": pathlib.Path("/sys/class/net/lo/mtu").read_text().strip(),
                "python": sys.version, "load_average": os.getloadavg(), "allowed_cpus": sorted(allowed), "proxy_cpu": args.proxy_cpu,
                "peer_cpus": sorted(peers), "clock_ticks": os.sysconf("SC_CLK_TCK"), "sing_box": version.strip(),
                "gcc": subprocess.run(["g++", "--version"], check=True, capture_output=True, text=True).stdout.splitlines()[0],
                "mcpp": subprocess.run(["mcpp", "--version"], check=True, capture_output=True, text=True).stdout.strip(),
                "benchmark_sha256": sha256(pathlib.Path(__file__)), "source_sha256": source_hashes,
                "baseline_sha256": sha256(args.baseline), "candidate_sha256": sha256(args.candidate),
                "rounds": args.rounds, "mib": args.mib}
    with tempfile.TemporaryDirectory(prefix="nexus-stream-bench-") as directory, args.output.open("x") as output:
        root = pathlib.Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key",
                        "-out", root / "cert", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-days", "1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root / "key").chmod(0o600)
        (root / "uuid").write_text(UUID + "\n"); (root / "uuid").chmod(0o600)
        (root / "ss-key").write_text(PASSWORD + "\n"); (root / "ss-key").chmod(0o600)
        print(json.dumps(metadata), file=output, flush=True)
        for round_number in range(args.rounds + 1):
            order = [("baseline", args.baseline), ("candidate", args.candidate)]
            if round_number % 2:
                order.reverse()
            for name, binary in order:
                record = {"kind": "sample", "binary": name, "round": round_number, "warmup": round_number == 0}
                with tempfile.TemporaryFile() as errors_file:
                    try:
                        record.update(sample(binary, args.mode, args.mib * 1024 * 1024, args.proxy_cpu, args.peer_cpus, root, errors_file))
                        record["status"] = "ok"
                    except Exception as exc:
                        errors_file.seek(0)
                        record.update(status="failed", error=repr(exc), stderr=errors_file.read().decode(errors="replace"))
                    print(json.dumps(record), file=output, flush=True)
                    print(json.dumps(record), flush=True)
                    if record["status"] != "ok":
                        raise RuntimeError("sample failed; see output for details")


if __name__ == "__main__":
    main()
