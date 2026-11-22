#!/usr/bin/env python3
"""Measure production SOCKS admission and mixed DNS/TCP load on Linux."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import resource
import socket
import struct
import tempfile
import time

from detour_network import reserve, running
from dns_rule_support import DnsPeer, dns_request, wire_name


CLOCK_TICKS = os.sysconf("SC_CLK_TCK")
PAYLOAD = bytes(range(256)) * 256


def measurements(pid):
    proc = Path("/proc") / str(pid)
    counts = {"fd": 0, "socket": 0, "pipe": 0, "timerfd": 0}
    for fd in (proc / "fd").iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        counts["fd"] += 1
        counts["socket"] += target.startswith("socket:[")
        counts["pipe"] += target.startswith("pipe:[")
        counts["timerfd"] += target == "anon_inode:[timerfd]"
    fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
    counts["cpu_ticks"] = int(fields[11]) + int(fields[12])
    for row in (proc / "status").read_text().splitlines():
        label, _, value = row.partition(":")
        if label in ("VmRSS", "VmHWM", "VmSize"):
            counts[label] = int(value.split()[0])
    return counts


def p99(samples):
    ordered = sorted(samples)
    return round(1000 * ordered[(99 * len(ordered) - 1) // 100], 3)


def report(**fields):
    print(json.dumps(fields, sort_keys=True), flush=True)


def config_text(root, front, cap, pipes, dns_port=0, upstream=None, extra_inbound=""):
    dns = f"""dns {{
    listen host="127.0.0.1" port={dns_port}
    server "upstream" type="udp" host="127.0.0.1" port={upstream}
    final "upstream"
}}
""" if upstream is not None else ""
    return f"""schema-version 1
role "client"
workers 2
sessions-per-listener {cap}
tcp-splice-pipes {pipes}
shutdown-grace-ms 4000
control socket="{root / 'control'}"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
{extra_inbound}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
{dns}"""


async def echo(reader, writer):
    try:
        while chunk := await reader.read(len(PAYLOAD)):
            writer.write(chunk)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def socks(front, target):
    reader, writer = await asyncio.open_connection("127.0.0.1", front)
    try:
        writer.write(b"\x05\x01\x00")
        assert await reader.readexactly(2) == b"\x05\x00"
        writer.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target))
        response = await reader.readexactly(10)
        if response[:4] != b"\x05\x00\x00\x01":
            raise ConnectionError(f"SOCKS CONNECT rejected: {response!r}")
        return reader, writer
    except BaseException:
        writer.close()
        raise


async def roundtrip(reader, writer, payload):
    writer.write(payload)
    await writer.drain()
    assert await reader.readexactly(len(payload)) == payload


async def close_all(clients):
    for _, writer in clients:
        writer.close()
    await asyncio.gather(*(writer.wait_closed() for _, writer in clients))


async def settle(pid, idle, timeout=7, lazy_timers=2):
    deadline = time.monotonic() + timeout
    while True:
        metrics = measurements(pid)
        new_timers = metrics["timerfd"] - idle["timerfd"]
        if (0 <= new_timers <= lazy_timers and metrics["fd"] == idle["fd"] + new_timers and
            all(metrics[k] == idle[k] for k in ("socket", "pipe"))):
            return metrics
        if time.monotonic() >= deadline:
            raise AssertionError(f"descriptors did not recover to {idle}: {metrics}")
        await asyncio.sleep(.025)


async def hold(front, target, sessions):
    async def one(index):
        start = time.monotonic()
        reader, writer = await socks(front, target)
        await roundtrip(reader, writer, struct.pack("!I", index))
        return (reader, writer), time.monotonic() - start

    clients, times = [], []
    for start in range(0, sessions, 64):
        group = await asyncio.gather(*(one(i) for i in range(start, min(start + 64, sessions))))
        for client, elapsed in group:
            clients.append(client)
            times.append(elapsed)
    return clients, times


async def capacity(command, target, levels, pipes):
    with tempfile.TemporaryDirectory(prefix="nexus-capacity-") as folder:
        root = Path(folder)
        front = reserve()
        config = root / "proxy.kdl"
        config.write_text(config_text(root, front, max(levels), pipes))
        with running([*command, "run", "--config", config], front, root / "run.log") as proxy:
            await asyncio.sleep(.12)
            idle = measurements(proxy.pid)
            for level in levels:
                async with asyncio.timeout(30):
                    begin = time.monotonic()
                    clients, times = await hold(front, target, level)
                    peak = measurements(proxy.pid)
                    elapsed = time.monotonic() - begin
                    assert peak["socket"] == idle["socket"] + 2 * level, (idle, peak)
                    assert peak["pipe"] <= idle["pipe"] + 2 * min(2 * level, pipes), (idle, peak)
                    await close_all(clients)
                    final = await settle(proxy.pid, idle)
                    report(mode="capacity", sessions=level, pipes=pipes, idle=idle, peak=peak,
                           final=final, admission_ms=round(1000 * elapsed, 3), connect_p99_ms=p99(times))


async def dns_client(port, worker, count):
    template = b"\x01\x00" + struct.pack("!4H", 1, 0, 0, 0) + wire_name("mixed-capacity.test") + b"\0\x01\0\x01"
    loop = asyncio.get_running_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.connect(("127.0.0.1", port))
        client.setblocking(False)
        times = []
        for index in range(count):
            identifier = struct.pack("!H", worker * count + index)
            start = time.monotonic()
            await loop.sock_sendall(client, identifier + template)
            reply = await loop.sock_recv(client, 1024)
            assert reply[:2] == identifier and reply[-4:] == b"\x7f\x00\x00\x01", reply
            times.append(time.monotonic() - start)
        return times


async def mixed(command, target, pipes, short_count, long_count, long_mib, dns_count, rounds):
    async def short_worker(front, count):
        samples = []
        for index in range(count):
            start = time.monotonic()
            reader, writer = await socks(front, target)
            try:
                await roundtrip(reader, writer, struct.pack("!I", index))
            finally:
                writer.close()
                await writer.wait_closed()
            samples.append(time.monotonic() - start)
        return samples

    async def long_flow(front):
        reader, writer = await socks(front, target)
        try:
            for _ in range(long_mib * 16):
                await roundtrip(reader, writer, PAYLOAD)
            writer.write_eof()
            assert await reader.read() == b""
        finally:
            writer.close()
            await writer.wait_closed()

    with tempfile.TemporaryDirectory(prefix="nexus-mixed-capacity-") as folder, DnsPeer() as peer:
        root = Path(folder)
        front, dns_port = reserve(), reserve()
        config = root / "proxy.kdl"
        config.write_text(config_text(root, front, 512, pipes, dns_port, peer.port))
        with running([*command, "run", "--config", config], front, root / "run.log") as proxy:
            await asyncio.sleep(.12)
            assert await asyncio.to_thread(dns_request, dns_port, "mixed-capacity.test") == (0, "127.0.0.1")
            idle = measurements(proxy.pid)
            peak = {}

            async def sample():
                while True:
                    current = measurements(proxy.pid)
                    for field in ("fd", "socket", "pipe", "VmRSS"):
                        peak[field] = max(current[field], peak.get(field, 0))
                    await asyncio.sleep(.025)

            sampling = asyncio.create_task(sample())
            begin = time.monotonic()
            short_times, dns_times = [], []
            try:
                for _ in range(rounds):
                    async with asyncio.timeout(45):
                        short, _, dns = await asyncio.gather(
                            asyncio.gather(*(short_worker(front, short_count) for _ in range(16))),
                            asyncio.gather(*(long_flow(front) for _ in range(long_count))),
                            asyncio.gather(*(dns_client(dns_port, worker, dns_count) for worker in range(4))),
                        )
                    short_times.extend(value for batch in short for value in batch)
                    dns_times.extend(value for batch in dns for value in batch)
            finally:
                sampling.cancel()
                await asyncio.gather(sampling, return_exceptions=True)
            seconds = time.monotonic() - begin
            final = await settle(proxy.pid, idle)
            assert 1 <= len(peer.seen) <= 1 + 4 * int(seconds // 59), peer.seen
            relay_bytes = rounds * 2 * (long_count * long_mib * 1024**2 + short_count * 16 * 4)
            cpu_ns = (final["cpu_ticks"] - idle["cpu_ticks"]) * 1e9 / CLOCK_TICKS
            report(mode="mixed", pipes=pipes, rounds=rounds, short_flows=rounds * short_count * 16,
                   long_flows=rounds * long_count, dns_queries=rounds * dns_count * 4,
                   upstream_dns_queries=len(peer.seen), relay_bytes=relay_bytes, seconds=round(seconds, 4),
                   total_relay_mib_s=round(relay_bytes / 1024**2 / seconds, 3),
                   proxy_cpu_ns_per_relay_byte=round(cpu_ns / relay_bytes, 4),
                   short_p99_ms=p99(short_times), dns_p99_ms=p99(dns_times),
                   idle=idle, peak=peak, final=final)


async def main(args):
    origin = await asyncio.start_server(echo, "127.0.0.1", backlog=1024)
    command = ["taskset", "-c", args.proxy_cpus, args.binary] if args.proxy_cpus else [args.binary]
    async with origin:
        target = origin.sockets[0].getsockname()[1]
        if args.mode == "capacity":
            await capacity(command, target, args.levels, args.pipes)
        else:
            await mixed(command, target, args.pipes, args.short_per_worker, args.long_flows,
                        args.long_mib, args.dns_per_worker, args.rounds)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda value: str(Path(value).resolve(strict=True)))
    parser.add_argument("mode", choices=("capacity", "mixed"))
    parser.add_argument("--proxy-cpus")
    parser.add_argument("--pipes", type=int, default=16)
    parser.add_argument("--levels", type=int, nargs="+", default=[64, 256, 512, 1024, 2048])
    parser.add_argument("--short-per-worker", type=int, default=50)
    parser.add_argument("--long-flows", type=int, default=12)
    parser.add_argument("--long-mib", type=int, default=16)
    parser.add_argument("--dns-per-worker", type=int, default=1000)
    parser.add_argument("--rounds", type=int, default=1)
    args = parser.parse_args()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    needed = 5 * max(args.levels) + 128
    if soft < needed:
        resource.setrlimit(resource.RLIMIT_NOFILE, (needed, hard))
    asyncio.run(main(args))
