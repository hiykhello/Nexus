#!/usr/bin/env python3
"""Fixed-offer loopback SOCKS/DNS comparison; records skips and failures."""
import argparse
import asyncio
import collections
import json
import os
import pathlib
import socket
import struct
import time


class Dns(asyncio.DatagramProtocol):
    def __init__(self, ttl):
        self.ttl = ttl
        self.counts = collections.Counter()
        self.errors = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        try:
            labels, pos = [], 12
            while data[pos]:
                length = data[pos]
                if length > 63:
                    raise ValueError("invalid DNS label")
                labels.append(data[pos + 1:pos + 1 + length].decode("ascii").lower())
                pos += length + 1
            pos += 1
            qtype, qclass = struct.unpack_from("!HH", data, pos)
            if qclass != 1 or qtype not in (1, 28) or pos + 4 != len(data):
                raise ValueError("unexpected DNS question")
            name = ".".join(labels)
            if not name.endswith(".example.test"):
                raise ValueError("unexpected DNS name")
            self.counts[("miss" if name.startswith("miss-") else "answer") + str(qtype)] += 1
            question = data[12:]
            if name.startswith("miss-") or qtype == 28:
                flags = b"\x81\x83" if name.startswith("miss-") else b"\x81\x80"
                soa = b"\xc0\x0c\x00\x06\x00\x01" + struct.pack("!IH", self.ttl, 24)
                soa += b"\xc0\x0c\xc0\x0c" + struct.pack("!IIIII", 1, 1, 1, 1, self.ttl)
                response = data[:2] + flags + b"\x00\x01\x00\x00\x00\x01\x00\x00" + question + soa
            else:
                answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!IH", self.ttl, 4) + b"\x7f\x00\x00\x01"
                response = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer
            self.transport.sendto(response, peer)
        except Exception as error:
            self.errors.append(repr(error))

    def error_received(self, error):
        self.errors.append(repr(error))


class Origin:
    def __init__(self):
        self.errors = []
        self.count = 0
        self.tasks = set()

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            token = await asyncio.wait_for(reader.readexactly(8), 3)
            writer.write(token)
            await writer.drain()
            self.count += 1
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError) as error:
            self.errors.append(type(error).__name__)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            self.tasks.discard(task)


async def request(port, origin_port, name, token, expect_negative, timeout):
    stage = "tcp-connect"
    async def exchange():
        nonlocal stage
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            stage = "socks-greeting"
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            if await reader.readexactly(2) != b"\x05\x00":
                raise RuntimeError("SOCKS greeting")
            domain = name.encode("ascii")
            writer.write(b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + struct.pack("!H", origin_port))
            await writer.drain()
            stage = "socks-reply"
            reply = await reader.readexactly(10)
            if expect_negative:
                if reply[:3] != b"\x05\x04\x00":
                    raise RuntimeError("unexpected negative reply " + reply[:3].hex())
                return
            if reply[:3] != b"\x05\x00\x00":
                raise RuntimeError("SOCKS connect " + reply[:3].hex())
            payload = struct.pack("!Q", token)
            writer.write(payload)
            await writer.drain()
            stage = "relay-reply"
            if await reader.readexactly(8) != payload:
                raise RuntimeError("payload mismatch")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
    try:
        await asyncio.wait_for(exchange(), timeout)
    except TimeoutError as error:
        raise TimeoutError(stage) from error


def quantile(values, probability):
    if not values:
        return None
    values = sorted(values)
    return values[int((len(values) - 1) * probability)]


def process_stats(pid):
    status = pathlib.Path(f"/proc/{pid}/status").read_text().splitlines()
    memory = {line.split(":", 1)[0]: int(line.split()[1]) for line in status
              if line.startswith(("VmRSS:", "VmHWM:"))}
    tail = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    memory["cpu_ticks"] = int(tail[11]) + int(tail[12])
    return memory


def socket_stats(pid):
    result = {"proxy_fds": len(os.listdir(f"/proc/{pid}/fd"))}
    for line in pathlib.Path("/proc/net/sockstat").read_text().splitlines():
        words = line.split()
        if words[0] in ("TCP:", "UDP:"):
            for key, value in zip(words[1::2], words[2::2]):
                if key in ("inuse", "tw", "alloc"):
                    result[words[0][:-1].lower() + "_" + key] = int(value)
    return result


async def run(args):
    if args.harness_cpus:
        os.sched_setaffinity(0, {int(cpu) for cpu in args.harness_cpus.split(",")})
    loop = asyncio.get_running_loop()
    # The resolver conservatively subtracts a whole second from the wire TTL,
    # and a cache hit requires at least another second remaining.
    ttl = 4 if args.scenario == "expiry" else 600
    dns = Dns(ttl)
    dns_transport, _ = await loop.create_datagram_endpoint(lambda: dns, local_addr=("127.0.0.1", 0))
    dns_port = dns_transport.get_extra_info("sockname")[1]
    origin = Origin()
    origin_server = await asyncio.start_server(origin.handle, "127.0.0.1", 0, backlog=512)
    origin_port = origin_server.sockets[0].getsockname()[1]
    command = [str(args.fixture), str(dns_port), str(args.workers)]
    if args.proxy_cpus:
        command = ["taskset", "-c", args.proxy_cpus] + command
    proc = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    phase = "startup"
    monitor_task = None
    try:
        line = (await asyncio.wait_for(proc.stdout.readline(), 10)).decode().split()
        if len(line) != 3 or line[0] != "ready" or line[2] != args.mode:
            raise RuntimeError(f"fixture did not start: {line}")
        port = int(line[1])
        names = [f"host-{index}.example.test" for index in range(64)]
        phase = "warmup"
        if args.scenario in ("hot", "uniform"):
            warm_names = names[:1] if args.scenario == "hot" else names
            for turn in range(args.warm_rounds):
                for begin in range(0, len(warm_names), args.inflight):
                    batch = warm_names[begin:begin + args.inflight]
                    await asyncio.gather(*(request(port, origin_port, name, turn * 64 + i, False, args.timeout)
                                           for i, name in enumerate(batch)))
        dns_before = dns.counts.copy()
        origin_before = origin.count
        before = process_stats(proc.pid)
        phase = "measurement"
        socket_peaks = collections.Counter()
        if args.diagnostics:
            async def monitor():
                while True:
                    for key, value in socket_stats(proc.pid).items():
                        socket_peaks[key] = max(socket_peaks[key], value)
                    await asyncio.sleep(0.25)
            monitor_task = asyncio.create_task(monitor())
        results = collections.Counter()
        latency, service, lag = [], [], []
        pending = set()
        peak_inflight = 0
        interval = 1_000_000_000 // (args.rate // args.burst)
        offered = args.seconds * args.rate
        groups = offered // args.burst
        start = time.monotonic_ns() + 200_000_000

        async def one(slot, scheduled):
            begun = time.monotonic_ns()
            name = (f"miss-{slot}.example.test" if args.scenario == "miss" else
                    names[0 if args.scenario == "hot" else
                          ((slot // args.burst if args.scenario == "expiry" else slot) * 37) % len(names)])
            try:
                await request(port, origin_port, name, slot, args.scenario == "miss", args.timeout)
            except Exception as error:
                results["failed"] += 1
                results["failure:" + type(error).__name__ + ":" + str(error)[:80]] += 1
            else:
                ended = time.monotonic_ns()
                results["completed"] += 1
                latency.append((ended - scheduled) // 1000)
                service.append((ended - begun) // 1000)
                lag.append((begun - scheduled) // 1000)

        group = 0
        while group < groups:
            scheduled = start + group * interval
            now = time.monotonic_ns()
            while now < scheduled:
                await asyncio.sleep((scheduled - now) / 1_000_000_000)
                now = time.monotonic_ns()
            late = min((now - scheduled) // interval, groups - group)
            results["skipped_late"] += late * args.burst
            group += late
            if group == groups:
                break
            scheduled = start + group * interval
            for offset in range(args.burst):
                if len(pending) >= args.inflight:
                    results["skipped_inflight"] += 1
                else:
                    task = asyncio.create_task(one(group * args.burst + offset, scheduled))
                    pending.add(task)
                    task.add_done_callback(pending.discard)
                    peak_inflight = max(peak_inflight, len(pending))
                    results["started"] += 1
            group += 1
        if pending:
            await asyncio.gather(*pending)
        after = process_stats(proc.pid)
        if monitor_task:
            monitor_task.cancel()
            await asyncio.gather(monitor_task, return_exceptions=True)
            monitor_task = None
        phase = "stop"
        proc.stdin.write(b"stop\n")
        await proc.stdin.drain()
        stopped = (await asyncio.wait_for(proc.stdout.readline(), 10)).decode().split()
        await asyncio.wait_for(proc.wait(), 10)
        stderr = (await proc.stderr.read()).decode()
        if proc.returncode or len(stopped) != 2 or stopped[0] != "stopped":
            raise RuntimeError(f"fixture stop failed {proc.returncode}, {stopped}, {stderr}")
        if dns.errors:
            raise RuntimeError(f"local DNS peer errors: {dns.errors[:4]}")
        if results["started"] + results["skipped_late"] + results["skipped_inflight"] != offered:
            raise RuntimeError("offered count mismatch")
        if results["completed"] + results["failed"] != results["started"]:
            raise RuntimeError("started count mismatch")
        answer = {"mode": args.mode, "scenario": args.scenario, "workers": args.workers,
                  "seconds": args.seconds, "rate": args.rate, "burst": args.burst, "inflight_limit": args.inflight,
                  "warm_rounds": args.warm_rounds, "ttl_seconds": ttl, "offered": offered,
                  "counts": dict(results), "peak_inflight": peak_inflight,
                  "warm_dns_queries": dict(dns_before), "dns_queries": dict(dns.counts - dns_before),
                  "origin_completed": origin.count - origin_before,
                  "origin_errors": dict(collections.Counter(origin.errors)),
                  "memory_before_kib": {k: before.get(k) for k in ("VmRSS", "VmHWM")},
                  "memory_after_kib": {k: after.get(k) for k in ("VmRSS", "VmHWM")},
                  "proxy_cpu_ticks": after["cpu_ticks"] - before["cpu_ticks"],
                  "stop_us": int(stopped[1]), "harness_cpus": args.harness_cpus,
                  "proxy_cpus": args.proxy_cpus, "diagnostic_socket_peaks": dict(socket_peaks),
                  "network_namespace": os.readlink("/proc/self/ns/net")}
        for label, values in (("scheduled_latency_us", latency), ("service_us", service), ("start_lag_us", lag)):
            answer[label] = {str(p): quantile(values, p) for p in (0.5, 0.99, 0.999)}
        print(json.dumps(answer, sort_keys=True), flush=True)
    except Exception as error:
        print(json.dumps({"mode": args.mode, "scenario": args.scenario, "phase": phase,
                          "aborted": type(error).__name__ + ":" + str(error),
                          "dns_queries_so_far": dict(dns.counts), "dns_errors": dns.errors,
                          "origin_errors": dict(collections.Counter(origin.errors)),
                          "fixture_returncode": proc.returncode}, sort_keys=True), flush=True)
        raise
    finally:
        if monitor_task:
            monitor_task.cancel()
            await asyncio.gather(monitor_task, return_exceptions=True)
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        dns_transport.close()
        origin_server.close()
        await origin_server.wait_closed()
        if origin.tasks:
            await asyncio.gather(*origin.tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("mode", choices=("per-worker", "shared", "snapshot", "group"))
    parser.add_argument("scenario", choices=("hot", "uniform", "miss", "expiry"))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--rate", type=int, default=1000)
    parser.add_argument("--burst", type=int, default=1)
    parser.add_argument("--inflight", type=int, default=48)
    parser.add_argument("--warm-rounds", type=int, default=24)
    parser.add_argument("--timeout", type=float, default=3)
    parser.add_argument("--proxy-cpus", default="")
    parser.add_argument("--harness-cpus", default="")
    parser.add_argument("--diagnostics", action="store_true")
    args = parser.parse_args()
    if not (2 <= args.workers <= 16 and 0 < args.seconds <= 3600 and 0 < args.rate <= 100000
            and 0 < args.burst <= args.inflight <= 48 and args.rate % args.burst == 0
            and args.warm_rounds > 0 and args.timeout > 0):
        parser.error("invalid worker, rate, duration, concurrency, warmup, or timeout")
    args.fixture = args.fixture.resolve(strict=True)
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
