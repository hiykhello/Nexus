#!/usr/bin/env python3
"""Bounded fixed-offer comparison of one or two real SOCKS inbounds."""
import argparse
import asyncio
import collections
import json
import os
import pathlib
import time

from proxy_bench import Dns, Origin, process_stats, quantile, request


def percentiles(values):
    return {str(p): quantile(values, p) for p in (0.5, 0.99, 0.999)}


async def run(args):
    loop = asyncio.get_running_loop()
    dns = Dns(600)
    transport, _ = await loop.create_datagram_endpoint(lambda: dns, local_addr=("127.0.0.1", 0))
    origin = Origin()
    listener = await asyncio.start_server(origin.handle, "127.0.0.1", 0)
    origin_port = listener.sockets[0].getsockname()[1]
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            str(args.fixture.resolve()), str(transport.get_extra_info("sockname")[1]), str(args.groups),
            str(args.capacity), str(args.workers), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        ready = (await asyncio.wait_for(process.stdout.readline(), 10)).decode().split()
        if len(ready) != args.groups + 3 or ready[:2] != ["ready", str(args.groups)] or ready[-1] != args.mode:
            raise RuntimeError(f"unexpected fixture startup: {ready!r}")
        ports = list(map(int, ready[2:-1]))
        names = [[f"load-{0 if args.layout == 'overlap' else group}-{index:03}.example.test"
                  for index in range(64)] for group in range(args.groups)]
        for group in range(args.groups):
            for index, name in enumerate(names[group]):
                await request(ports[group], origin_port, name, group * 64 + index, False, 5)
        warm_dns = dns.counts.copy()
        prior_origin = origin.count
        before = process_stats(process.pid)
        harness_before = time.process_time_ns()
        load_before = os.getloadavg()

        total_rate = args.rate_per_group * args.groups
        interval_ns = 1_000_000_000 // total_rate
        offered = args.seconds * total_rate
        start_ns = time.monotonic_ns() + 150_000_000
        completion = [[] for _ in ports]
        service = [[] for _ in ports]
        start_lag = [[] for _ in ports]
        successes = [0 for _ in ports]
        errors = collections.Counter()
        pending = set()
        launched = skipped_late = skipped_capacity = peak_pending = 0

        async def perform(slot, scheduled_ns):
            group = slot % args.groups
            name = names[group][(slot // args.groups) % 64]
            began = time.monotonic_ns()
            try:
                await request(ports[group], origin_port, name, slot + 1, False, 5)
            except Exception as error:
                errors[f"{type(error).__name__}: {error}"] += 1
            else:
                ended = time.monotonic_ns()
                successes[group] += 1
                completion[group].append((ended - scheduled_ns) // 1000)
                service[group].append((ended - began) // 1000)
                start_lag[group].append((began - scheduled_ns) // 1000)

        slot = 0
        while slot < offered:
            due = start_ns + slot * interval_ns
            delay = (due - time.monotonic_ns()) / 1_000_000_000
            if delay > 0:
                await asyncio.sleep(delay)
            now = time.monotonic_ns()
            missed = max(0, (now - due) // interval_ns)
            if missed:
                missed = min(missed, offered - slot)
                skipped_late += missed
                slot += missed
                if slot == offered:
                    break
                due = start_ns + slot * interval_ns
            if len(pending) >= args.inflight:
                skipped_capacity += 1
            else:
                task = asyncio.create_task(perform(slot, due))
                pending.add(task)
                task.add_done_callback(pending.discard)
                launched += 1
                peak_pending = max(peak_pending, len(pending))
            slot += 1
        if pending:
            await asyncio.gather(*tuple(pending))
        ended_ns = time.monotonic_ns()
        after = process_stats(process.pid)
        harness_cpu_ms = (time.process_time_ns() - harness_before) / 1_000_000
        during_dns = dns.counts - warm_dns
        stats = None
        if args.mode == "group":
            process.stdin.write(b"stats\n")
            await process.stdin.drain()
            stats = (await asyncio.wait_for(process.stdout.readline(), 5)).decode().split()
        process.stdin.write(b"stop\n")
        await process.stdin.drain()
        stopped = (await asyncio.wait_for(process.stdout.readline(), 10)).decode().split()
        exit_code = await asyncio.wait_for(process.wait(), 10)
        if stopped != ["stopped"] or exit_code:
            raise RuntimeError(f"fixture stop failed: {stopped}, {exit_code}")
        if dns.errors or origin.errors:
            raise RuntimeError(f"network peer errors: {dns.errors!r}, {origin.errors!r}")
        completed = sum(successes)
        result = {
            "run": args.run, "mode": args.mode, "groups": args.groups, "workers_per_group": args.workers,
            "layout": args.layout, "memberships": args.capacity, "total_rate": total_rate,
            "seconds": args.seconds, "offered": offered, "launched": launched, "completed": completed,
            "successful_by_group": successes, "skipped_late": skipped_late, "skipped_capacity": skipped_capacity,
            "errors": dict(errors), "peak_pending": peak_pending,
            "duration_ms": (ended_ns - start_ns) / 1_000_000,
            "completion_us": [percentiles(items) for items in completion],
            "service_us": [percentiles(items) for items in service],
            "start_lag_us": [percentiles(items) for items in start_lag],
            "dns_during": dict(during_dns), "dns_warm": dict(warm_dns), "origin_delivered": origin.count - prior_origin,
            "proxy_before": before, "proxy_after": after, "proxy_cpu_ticks": after["cpu_ticks"] - before["cpu_ticks"],
            "harness_cpu_ms": harness_cpu_ms, "system_load_before": load_before, "group_stats": stats,
        }
        result["valid_no_drop"] = (offered == launched == completed and not errors and
                                   not skipped_late and not skipped_capacity and
                                   origin.count - prior_origin == completed and not during_dns)
        print(json.dumps(result, sort_keys=True), flush=True)
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        listener.close()
        await listener.wait_closed()
        transport.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--mode", choices=("baseline", "group"), required=True)
    parser.add_argument("--groups", type=int, choices=(1, 2), required=True)
    parser.add_argument("--layout", choices=("overlap", "disjoint"), required=True)
    parser.add_argument("--capacity", type=int, default=512)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--rate-per-group", type=int, default=60)
    parser.add_argument("--seconds", type=int, default=3)
    parser.add_argument("--inflight", type=int, default=32)
    parser.add_argument("--run", type=int, default=1)
    arguments = parser.parse_args()
    if (arguments.capacity < arguments.groups * 128 or arguments.capacity > 8192 or
            not 1 <= arguments.workers <= 8 or not 1 <= arguments.rate_per_group <= 10000 or
            not 1 <= arguments.seconds <= 60 or not 1 <= arguments.inflight <= 4096):
        parser.error("invalid benchmark bounds")
    asyncio.run(run(arguments))
