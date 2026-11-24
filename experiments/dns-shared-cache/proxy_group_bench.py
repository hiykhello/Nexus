#!/usr/bin/env python3
"""Fixed-offer two-SOCKS/two-SS-UDP comparison in one network namespace."""
import argparse
import asyncio
import base64
import collections
import gc
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import time

from proxy_bench import Dns, Origin, process_stats, quantile, request


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Echo(asyncio.DatagramProtocol):
    def __init__(self, trace=False):
        self.count = 0
        self.errors = []
        self.trace = trace
        self.seen = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        self.count += 1
        if self.trace:
            if len(data) != 8:
                self.errors.append("unexpected target payload length")
            else:
                self.seen[struct.unpack("!Q", data)[0]] = time.monotonic_ns()
        self.transport.sendto(data, peer)

    def error_received(self, error):
        self.errors.append(repr(error))


class UdpClient(asyncio.DatagramProtocol):
    def __init__(self, target_port, echo):
        self.target_port = target_port
        self.echo = echo
        self.pending = {}
        self.errors = []
        self.extra = 0
        self.trace = []
        self.measurement_start_ns = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        try:
            if len(data) < 10 or data[:3] != b"\x00\x00\x00":
                raise ValueError("invalid SOCKS UDP header")
            if data[3] == 1:
                host, end = socket.inet_ntoa(data[4:8]), 10
            elif data[3] == 3:
                length = data[4]
                end = 7 + length
                host = data[5:5 + length].decode("ascii")
            elif data[3] == 4:
                host, end = socket.inet_ntop(socket.AF_INET6, data[4:20]), 22
            else:
                raise ValueError("unknown SOCKS UDP address")
            if len(data) != end + 8 or struct.unpack("!H", data[end - 2:end])[0] != self.target_port:
                raise ValueError("invalid SOCKS UDP payload or port")
            token = struct.unpack("!Q", data[end:])[0]
            item = self.pending.get(token)
            if item is None or item[0].done():
                self.extra += 1
            elif host not in ("127.0.0.1", item[1]):
                raise ValueError("wrong SOCKS UDP origin " + host)
            else:
                if self.echo.trace:
                    arrived = self.echo.seen.pop(token, None)
                    if arrived is None:
                        raise ValueError("target did not observe UDP token")
                    received = time.monotonic_ns()
                    self.trace.append({"token": token, "to_origin_us": (arrived - item[2]) // 1000,
                                       "from_origin_us": (received - arrived) // 1000,
                                       "origin_at_us": (arrived - self.measurement_start_ns) // 1000,
                                       "response_at_us": (received - self.measurement_start_ns) // 1000})
                item[0].set_result(None)
        except Exception as error:
            self.errors.append(repr(error))

    def error_received(self, error):
        self.errors.append(repr(error))

    async def send(self, endpoint, name, token, timeout):
        future = asyncio.get_running_loop().create_future()
        if token in self.pending:
            raise RuntimeError("duplicate UDP token")
        self.pending[token] = (future, name, time.monotonic_ns() if self.echo.trace else 0)
        try:
            domain = name.encode("ascii")
            packet = (b"\x00\x00\x00\x03" + bytes([len(domain)]) + domain +
                      struct.pack("!HQ", self.target_port, token))
            self.transport.sendto(packet, endpoint)
            await asyncio.wait_for(future, timeout)
        finally:
            self.pending.pop(token, None)


async def associate(port, target_port, echo):
    deadline = time.monotonic() + 10
    while True:
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            await asyncio.sleep(.02)
    loop = asyncio.get_running_loop()
    transport, client = await loop.create_datagram_endpoint(
        lambda: UdpClient(target_port, echo), local_addr=("127.0.0.1", 0))
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await asyncio.wait_for(reader.readexactly(2), 5) != b"\x05\x00":
            raise RuntimeError("UDP SOCKS greeting failed")
        local_port = transport.get_extra_info("sockname")[1]
        writer.write(b"\x05\x03\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", local_port))
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(10), 5)
        if header[:4] != b"\x05\x00\x00\x01":
            raise RuntimeError("UDP SOCKS association failed")
        endpoint = (socket.inet_ntoa(header[4:8]), struct.unpack("!H", header[8:])[0])
        return writer, transport, client, endpoint
    except BaseException:
        transport.close()
        writer.close()
        await writer.wait_closed()
        raise


def qstats(values):
    return {str(p): quantile(values, p) for p in (0.5, 0.99, 0.999)}


async def run(args):
    if args.harness_cpus:
        os.sched_setaffinity(0, {int(cpu) for cpu in args.harness_cpus.split(",")})
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    version = subprocess.run([args.sing_box, "version"], check=True, capture_output=True, text=True).stdout
    if f"Revision: {revision}" not in version:
        raise RuntimeError("unexpected sing-box revision")
    loop = asyncio.get_running_loop()
    ttl = 4 if args.scenario == "expiry" else 600
    dns = Dns(ttl)
    dns_transport, _ = await loop.create_datagram_endpoint(lambda: dns, local_addr=("127.0.0.1", 53 if args.local_dns else 0))
    dns_port = dns_transport.get_extra_info("sockname")[1]
    origin = Origin()
    origin_server = await asyncio.start_server(origin.handle, "127.0.0.1", 0, backlog=512)
    target_port = origin_server.sockets[0].getsockname()[1]
    echo = Echo(args.trace_udp)
    echo_transport, _ = await loop.create_datagram_endpoint(lambda: echo, local_addr=("127.0.0.1", target_port))
    udp_ports = []
    while len(udp_ports) < 2:
        port = free_port(socket.SOCK_DGRAM)
        if port not in udp_ports:
            udp_ports.append(port)
    cli_directory = None
    if args.cli:
        cli_directory = tempfile.TemporaryDirectory(prefix="nexus-cli-bench-")
        root = pathlib.Path(cli_directory.name)
        tcp_ports = []
        while len(tcp_ports) < 2:
            port = free_port(socket.SOCK_STREAM)
            if port not in tcp_ports and port not in udp_ports:
                tcp_ports.append(port)
        for index in range(2):
            path = root / f"key-{index}"
            path.write_text(base64.b64encode(bytes(range(index * 16, (index + 1) * 16))).decode() + "\n")
            path.chmod(0o600)
        config = root / "server.kdl"
        routing = 'default-outbound "direct";'
        if args.rule_count:
            rule_path = root / "bench-rules.kdl"
            names = [f"host-{i}.example.test" for i in range(min(args.rule_count, 64))]
            names += [f"unused-{i}.long-example-domain.example" for i in range(args.rule_count - len(names))]
            predicates = (f'rule type="domain-suffix" value="{name}"\n' for name in names)
            if args.logical_rules:
                predicates = (f'rule type="and" {{ rule type="domain-suffix" value="{name}"; '
                              f'rule type="port-range" value="1-65535"; }}\n' for name in names)
            rule_path.write_text('schema-version 2\nkind "predicate"\n' + ''.join(predicates))
            routing = 'rule-set "bench" path="bench-rules.kdl" format="kdl"; rules { - kind="rule-set" value="bench" outbound="direct"; }; ' + routing
        dns_config = ('server "upstream" type="local";' if args.local_dns else
                      f'server "upstream" type="udp" host="127.0.0.1" port={dns_port};')
        config.write_text(f'''schema-version 1
role "server"
workers {args.workers}
inbounds {{
 socks5 "tcp0" {{ listen host="127.0.0.1" port={tcp_ports[0]}; authentication "none"; }}
 socks5 "tcp1" {{ listen host="127.0.0.1" port={tcp_ports[1]}; authentication "none"; }}
 shadowsocks "udp0" {{ listen host="127.0.0.1" port={udp_ports[0]}; method "2022-blake3-aes-128-gcm"; key-file "{root / "key-0"}"; }}
 shadowsocks "udp1" {{ listen host="127.0.0.1" port={udp_ports[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root / "key-1"}"; }}
}}
outbound "direct" type="direct"
routing {{ {routing} }}
dns {{ {dns_config} final "upstream"; }}
''')
        command = ["stdbuf", "-oL", str(args.fixture), "run", "--config", str(config)]
    else:
        command = [str(args.fixture), str(dns_port), str(args.workers), *map(str, udp_ports)]
    if args.proxy_cpus:
        command = ["taskset", "-c", args.proxy_cpus] + command
    fixture_env = os.environ.copy()
    if args.trace_udp:
        fixture_env["NEXUS_DNS_BENCH_TRACE_LOOP"] = "1"
    proc = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=fixture_env)
    phase, boxes, clients, results = "startup", [], [], []
    monitor_task, gc_callback = None, None
    try:
        if args.cli:
            for _ in range(4):
                line = (await asyncio.wait_for(proc.stdout.readline(), 10)).decode()
                if "listening" not in line:
                    raise RuntimeError(f"CLI listener did not start: {line!r}")
        else:
            line = (await asyncio.wait_for(proc.stdout.readline(), 10)).decode().split()
            if len(line) != 4 or line[0] != "ready" or line[3] != args.mode:
                raise RuntimeError(f"fixture did not start: {line}")
            tcp_ports = list(map(int, line[1:3]))
        with tempfile.TemporaryDirectory(prefix="nexus-group-bench-") as directory:
            for index, port in enumerate(udp_ports):
                socks_port = free_port(socket.SOCK_STREAM)
                key = bytes(range(index * 16, (index + 1) * 16))
                config = {"log": {"level": "warn"},
                          "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
                          "outbounds": [{"type": "shadowsocks", "tag": "edge", "server": "127.0.0.1",
                                         "server_port": port, "method": "2022-blake3-aes-128-gcm",
                                         "password": base64.b64encode(key).decode()}],
                          "route": {"final": "edge"}}
                path = pathlib.Path(directory) / f"client-{index}.json"
                path.write_text(json.dumps(config))
                box_command = [args.sing_box, "run", "-c", str(path)]
                if args.singbox_cpus:
                    box_command = ["taskset", "-c", args.singbox_cpus] + box_command
                box = await asyncio.create_subprocess_exec(*box_command, stdout=asyncio.subprocess.DEVNULL,
                                                            stderr=asyncio.subprocess.PIPE)
                boxes.append(box)
                clients.append(await associate(socks_port, target_port, echo))

            def name_for(endpoint, number):
                index = 0 if args.scenario == "hot" else (number * 37) % 64
                suffix = f"-{endpoint}" if args.scenario == "disjoint" else ""
                return f"host-{index}{suffix}.example.test"

            async def exchange(endpoint, name, token):
                if endpoint < 2:
                    await request(tcp_ports[endpoint], target_port, name, token, False, args.timeout)
                else:
                    _, _, client, peer = clients[endpoint - 2]
                    await client.send(peer, name, token, args.timeout)

            phase = "warmup"
            warm_count = 1 if args.scenario in ("hot", "expiry") else 64
            for endpoint in range(4):
                for begin in range(0, warm_count, args.burst):
                    await asyncio.gather(*(exchange(endpoint, name_for(endpoint, index),
                        (1 << 63) | (endpoint << 32) | index)
                        for index in range(begin, min(warm_count, begin + args.burst))))
            dns_before = dns.counts.copy()
            origin_before, echo_before = origin.count, echo.count
            echo.seen.clear()
            for _, _, client, _ in clients:
                client.trace.clear()
            before = process_stats(proc.pid)
            box_before = [process_stats(box.pid) for box in boxes]
            phase = "measurement"
            results = [collections.Counter() for _ in range(4)]
            latencies = [{"scheduled": [], "service": [], "lag": []} for _ in range(4)]
            pending = set()
            peak = 0
            interval = 1_000_000_000 // (args.rate // args.burst)
            offered = args.seconds * args.rate
            groups = offered // args.burst
            start = time.monotonic_ns() + 200_000_000
            stalls, collections_seen, gc_starts = [], [], {}
            if args.trace_udp:
                for _, _, client, _ in clients:
                    client.measurement_start_ns = start
                def observe_gc(phase, info):
                    now = time.monotonic_ns()
                    generation = info["generation"]
                    if phase == "start":
                        gc_starts[generation] = now
                    elif generation in gc_starts:
                        begun = gc_starts.pop(generation)
                        if now - begun >= 1_000_000:
                            collections_seen.append({"generation": generation, "start_us": (begun - start) // 1000,
                                                     "duration_us": (now - begun) // 1000})
                gc_callback = observe_gc
                gc.callbacks.append(gc_callback)
                async def monitor():
                    last_wall = time.monotonic_ns()
                    last_cpu = time.thread_time_ns()
                    next_wake = last_wall + 10_000_000
                    while True:
                        await asyncio.sleep(max(0, next_wake - time.monotonic_ns()) / 1_000_000_000)
                        now = time.monotonic_ns()
                        cpu = time.thread_time_ns()
                        if now - next_wake >= 5_000_000:
                            stalls.append({"expected_us": (next_wake - start) // 1000,
                                           "late_us": (now - next_wake) // 1000,
                                           "elapsed_us": (now - last_wall) // 1000,
                                           "thread_cpu_us": (cpu - last_cpu) // 1000})
                        last_wall, last_cpu = now, cpu
                        next_wake = now + 10_000_000
                monitor_task = asyncio.create_task(monitor())

            async def one(slot, scheduled):
                endpoint = slot % 4
                begun = time.monotonic_ns()
                number = slot // 4 if args.scenario != "expiry" else slot // args.burst
                try:
                    await exchange(endpoint, name_for(endpoint, number), slot)
                except Exception as error:
                    results[endpoint]["failed"] += 1
                    results[endpoint]["failure:" + type(error).__name__ + ":" + str(error)[:80]] += 1
                else:
                    ended = time.monotonic_ns()
                    results[endpoint]["completed"] += 1
                    latencies[endpoint]["scheduled"].append((ended - scheduled) // 1000)
                    latencies[endpoint]["service"].append((ended - begun) // 1000)
                    latencies[endpoint]["lag"].append((begun - scheduled) // 1000)

            group = 0
            while group < groups:
                scheduled = start + group * interval
                now = time.monotonic_ns()
                while now < scheduled:
                    await asyncio.sleep((scheduled - now) / 1_000_000_000)
                    now = time.monotonic_ns()
                late = min((now - scheduled) // interval, groups - group)
                for endpoint in range(4):
                    results[endpoint]["skipped_late"] += late * (args.burst // 4)
                group += late
                if group == groups:
                    break
                scheduled = start + group * interval
                for offset in range(args.burst):
                    slot = group * args.burst + offset
                    endpoint = slot % 4
                    if len(pending) >= args.inflight:
                        results[endpoint]["skipped_inflight"] += 1
                    else:
                        task = asyncio.create_task(one(slot, scheduled))
                        pending.add(task)
                        task.add_done_callback(pending.discard)
                        peak = max(peak, len(pending))
                        results[endpoint]["started"] += 1
                group += 1
            if pending:
                await asyncio.gather(*pending)
            if monitor_task:
                monitor_task.cancel()
                await asyncio.gather(monitor_task, return_exceptions=True)
                monitor_task = None
            if gc_callback:
                gc.callbacks.remove(gc_callback)
                gc_callback = None
            after = process_stats(proc.pid)
            box_after = [process_stats(box.pid) for box in boxes]
            phase = "stop"
            if args.cli:
                stop_start = time.monotonic_ns()
                proc.terminate()
                await asyncio.wait_for(proc.wait(), 10)
                stopped = ["stopped", str((time.monotonic_ns() - stop_start) // 1000)]
            else:
                proc.stdin.write(b"stop\n")
                await proc.stdin.drain()
                stopped = (await asyncio.wait_for(proc.stdout.readline(), 10)).decode().split()
                await asyncio.wait_for(proc.wait(), 10)
            stderr = (await proc.stderr.read()).decode()
            if proc.returncode or len(stopped) != 2 or stopped[0] != "stopped":
                raise RuntimeError(f"fixture stop failed {proc.returncode}, {stopped}, {stderr}")
            if dns.errors or echo.errors or any(client.errors for _, _, client, _ in clients):
                raise RuntimeError(f"peer errors: {dns.errors}, {echo.errors}, {[c.errors for _, _, c, _ in clients]}")
            for count in results:
                if count["started"] + count["skipped_late"] + count["skipped_inflight"] != offered // 4:
                    raise RuntimeError("offered count mismatch")
                if count["completed"] + count["failed"] != count["started"]:
                    raise RuntimeError("started count mismatch")
            if not any(count["failed"] for count in results):
                if origin.count - origin_before != sum(count["completed"] for count in results[:2]):
                    raise RuntimeError("TCP origin count mismatch")
                if echo.count - echo_before != sum(count["completed"] for count in results[2:]):
                    raise RuntimeError("UDP origin count mismatch")
                if any(client.extra for _, _, client, _ in clients):
                    raise RuntimeError("unexpected UDP reply")
            answer = {"mode": args.mode, "scenario": args.scenario, "workers_per_tcp": args.workers,
                      "seconds": args.seconds, "rate": args.rate, "burst": args.burst,
                      "inflight_limit": args.inflight, "offered": offered, "ttl_seconds": ttl,
                      "counts": {name: dict(count) for name, count in zip(("tcp0", "tcp1", "udp0", "udp1"), results)},
                      "latency_us": {name: {label: qstats(values) for label, values in data.items()}
                                     for name, data in zip(("tcp0", "tcp1", "udp0", "udp1"), latencies)},
                      "peak_inflight": peak, "warm_dns_queries": dict(dns_before),
                      "dns_queries": dict(dns.counts - dns_before),
                      "tcp_origin_completed": origin.count - origin_before, "udp_origin_packets": echo.count - echo_before,
                      "origin_errors": dict(collections.Counter(origin.errors)),
                      "udp_extra_replies": [client.extra for _, _, client, _ in clients],
                      "memory_before_kib": {k: before.get(k) for k in ("VmRSS", "VmHWM")},
                      "memory_after_kib": {k: after.get(k) for k in ("VmRSS", "VmHWM")},
                      "proxy_cpu_ticks": after["cpu_ticks"] - before["cpu_ticks"],
                      "singbox_cpu_ticks": [a["cpu_ticks"] - b["cpu_ticks"] for a, b in zip(box_after, box_before)],
                      "singbox_memory_after_kib": [{k: stats.get(k) for k in ("VmRSS", "VmHWM")} for stats in box_after],
                      "stop_us": int(stopped[1]), "proxy_cpus": args.proxy_cpus,
                      "harness_cpus": args.harness_cpus, "singbox_cpus": args.singbox_cpus,
                      "network_namespace": os.readlink("/proc/self/ns/net"), "singbox_revision": revision}
            if args.trace_udp:
                answer["udp_trace"] = {}
                answer["trace_start_monotonic_ns"] = start
                answer["udp_listener_ports"] = udp_ports
                answer["udp_echo_port"] = target_port
                answer["udp_client_ports"] = [transport.get_extra_info("sockname")[1]
                                              for _, transport, _, _ in clients]
                answer["udp_socks_ports"] = [endpoint[1] for _, _, _, endpoint in clients]
                answer["harness_loop_stalls"] = stalls
                answer["harness_gc_pauses"] = collections_seen
                answer["proxy_loop_stalls"] = []
                for line in stderr.splitlines():
                    fields = line.split()
                    if len(fields) == 4 and fields[0] == "bench-poll":
                        answer["proxy_loop_stalls"].append({"start_us": (int(fields[1]) - start) // 1000,
                                                            "elapsed_us": int(fields[2]), "thread_cpu_us": int(fields[3])})
                    elif len(fields) == 2 and fields[0] == "bench-poll-dropped":
                        answer["proxy_loop_stalls_dropped"] = int(fields[1])
                    else:
                        raise RuntimeError("unexpected diagnostic output: " + line)
                for index, (_, _, client, _) in enumerate(clients):
                    trace = client.trace
                    answer["udp_trace"][f"udp{index}"] = {
                        "to_origin_us": qstats([item["to_origin_us"] for item in trace]),
                        "from_origin_us": qstats([item["from_origin_us"] for item in trace]),
                        "slowest": sorted(trace, key=lambda item: item["to_origin_us"] + item["from_origin_us"], reverse=True)[:8]}
            print(json.dumps(answer, sort_keys=True), flush=True)
    except Exception as error:
        fixture_stderr = (await proc.stderr.read()).decode(errors="replace") if proc.returncode is not None else ""
        print(json.dumps({"mode": args.mode, "scenario": args.scenario, "phase": phase,
                          "aborted": type(error).__name__ + ":" + str(error),
                          "dns_queries_so_far": dict(dns.counts), "dns_errors": dns.errors,
                          "fixture_returncode": proc.returncode, "fixture_stderr": fixture_stderr[-16000:],
                          "counts_so_far": [dict(count) for count in results]}, sort_keys=True), flush=True)
        raise
    finally:
        if monitor_task:
            monitor_task.cancel()
            await asyncio.gather(monitor_task, return_exceptions=True)
        if gc_callback:
            gc.callbacks.remove(gc_callback)
        for writer, transport, _, _ in clients:
            transport.close()
            writer.close()
            await writer.wait_closed()
        for box in boxes:
            if box.returncode is None:
                box.terminate()
            await box.communicate()
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        if cli_directory:
            cli_directory.cleanup()
        dns_transport.close()
        echo_transport.close()
        origin_server.close()
        await origin_server.wait_closed()
        if origin.tasks:
            await asyncio.gather(*origin.tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("mode", choices=("shared", "group", "coordinator"))
    parser.add_argument("scenario", choices=("hot", "uniform", "disjoint", "expiry"))
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--seconds", type=int, default=4)
    parser.add_argument("--rate", type=int, default=800)
    parser.add_argument("--burst", type=int, default=8)
    parser.add_argument("--inflight", type=int, default=48)
    parser.add_argument("--timeout", type=float, default=3)
    parser.add_argument("--proxy-cpus", default="")
    parser.add_argument("--harness-cpus", default="")
    parser.add_argument("--singbox-cpus", default="")
    parser.add_argument("--sing-box", default="sing-box")
    parser.add_argument("--trace-udp", action="store_true", help="record target arrival and return timing for diagnosis")
    parser.add_argument("--cli", action="store_true", help="run the production Nexus CLI using a generated configuration")
    parser.add_argument("--local-dns", action="store_true", help="use the isolated system DNS endpoint on port 53")
    parser.add_argument("--rule-count", type=int, default=0, help="CLI domain rules for routing load")
    parser.add_argument("--logical-rules", action="store_true", help="wrap CLI domain rules in a port-constrained AND")
    args = parser.parse_args()
    if not (2 <= args.workers <= 8 and 0 < args.seconds <= 3600 and 0 < args.rate <= 100000
            and 4 <= args.burst <= args.inflight <= 48 and args.burst % 4 == 0
            and args.rate % args.burst == 0 and args.timeout > 0):
        parser.error("invalid worker, rate, duration, concurrency, or timeout")
    if not 0 <= args.rule_count <= 4000 or (args.rule_count and not args.cli):
        parser.error("--rule-count requires --cli and must be between 0 and 4000")
    if args.logical_rules and not args.rule_count:
        parser.error("--logical-rules requires a nonzero --rule-count")
    if args.local_dns and not args.cli:
        parser.error("--local-dns requires --cli")
    if args.cli and args.trace_udp:
        parser.error("CLI builds do not expose the benchmark trace hook")
    args.fixture = args.fixture.resolve(strict=True)
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
