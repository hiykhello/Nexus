#!/usr/bin/env python3
"""Check proxy capacity under Linux fd and address-space limits and listener reloads."""

import argparse
import asyncio
from pathlib import Path
import resource
import socket
import subprocess
import tempfile

from detour_network import reserve, running
from proxy_capacity_network import (
    close_all, config_text, echo, hold, measurements, report, roundtrip, settle, socks,
)


async def fd_pressure(command, target, root, limit):
    front = reserve()
    config = root / "fd.kdl"
    config.write_text(config_text(root, front, 512, 0))
    prefix = ["prlimit", f"--nofile={limit}:{limit}", "--"]
    with running([*prefix, *command, "run", "--config", config], front, root / "fd.log") as proxy:
        await asyncio.sleep(.12)
        idle = measurements(proxy.pid)
        live, _ = await hold(front, target, 24)
        pending = []
        try:
            for _ in range(4):
                pending.extend(await asyncio.gather(
                    *(asyncio.open_connection("127.0.0.1", front) for _ in range(64))))
            async with asyncio.timeout(4):
                while (peak := measurements(proxy.pid))["fd"] < limit:
                    await asyncio.sleep(.02)
            await asyncio.sleep(.15)
            assert proxy.poll() is None, (root / "fd.log").read_text()
            await roundtrip(*live[0], b"established-during-fd-pressure")
        finally:
            await close_all(pending)
            await close_all(live)
        final = await settle(proxy.pid, idle)
        recovered, _ = await hold(front, target, 24)
        await close_all(recovered)
        await settle(proxy.pid, final, lazy_timers=0)
        report(mode="fd-limit", limit=limit, idle=idle, peak=peak, final=final, recovered=len(recovered))


async def memory_limit(command, target, root, limit_mib, sessions):
    front = reserve()
    config = root / "memory.kdl"
    config.write_text(config_text(root, front, sessions, 16))
    limit = limit_mib * 1024 * 1024
    prefix = ["env", "MALLOC_ARENA_MAX=2", "prlimit", f"--as={limit}:{limit}", "--"]
    with running([*prefix, *command, "run", "--config", config], front, root / "memory.log") as proxy:
        await asyncio.sleep(.12)
        idle = measurements(proxy.pid)
        retained, _ = await hold(front, target, sessions)
        peak = measurements(proxy.pid)
        assert peak["VmSize"] <= limit // 1024
        assert peak["socket"] == idle["socket"] + sessions * 2
        try:
            async with asyncio.timeout(2):
                extra = await socks(front, target)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        else:
            await close_all([extra])
            raise AssertionError("admitted a TLS-free TCP session beyond the configured limit")
        await roundtrip(*retained[-1], b"established-with-address-space-limit")
        await close_all(retained)
        final = await settle(proxy.pid, idle)
        recovered, _ = await hold(front, target, sessions)
        await close_all(recovered)
        await settle(proxy.pid, idle)
        report(mode="memory-limit", limit_mib=limit_mib, sessions=sessions, idle=idle, peak=peak,
               final=final, recovered=len(recovered))


async def generations(binary, command, target, root):
    original = reserve()
    config = root / "generations.kdl"
    config.write_text(config_text(root, original, 256, 0))
    with running([*command, "run", "--config", config], original, root / "generations.log") as proxy:
        await asyncio.sleep(.12)
        idle = measurements(proxy.pid)
        all_clients = []
        used_ports = {original}
        try:
            for generation in range(1, 4):
                if generation > 1:
                    extra = reserve()
                    while extra in used_ports:
                        extra = reserve()
                    used_ports.add(extra)
                    config.write_text(config_text(root, original, 256, 0, extra_inbound=
                        f'inbound "extra" type="socks5" {{ listen host="127.0.0.1" port={extra}; authentication "none"; }}'))
                    accepted = subprocess.check_output([binary, "control", root / "control", "reload"], text=True)
                    operation = accepted.split()[0].removeprefix("id=")
                    async with asyncio.timeout(3):
                        while True:
                            state = subprocess.check_output(
                                [binary, "control", root / "control", "operation", operation], text=True)
                            if "state=pending" not in state:
                                break
                            await asyncio.sleep(.02)
                    assert f"state=succeeded control-generation={generation}" in state, state
                    status = subprocess.check_output([binary, "control", root / "control", "status"], text=True)
                    assert f"listener-generation={generation}\n" in status, status
                batch, _ = await hold(original, target, 64)
                all_clients.extend(batch)
                await asyncio.gather(*(roundtrip(*pair, b"across-reload") for pair in all_clients[::13]))
            peak = measurements(proxy.pid)
            assert peak["socket"] >= idle["socket"] + 2 * len(all_clients), peak
        finally:
            await close_all(all_clients)
        # The latest generation has one additional listener and readiness fd
        # per worker. Poll status for zero remaining activity after old leases drain.
        async with asyncio.timeout(8):
            while True:
                state = subprocess.check_output([binary, "control", root / "control", "status"], text=True)
                final = measurements(proxy.pid)
                rows = [row for row in state.splitlines() if row.startswith("listener=")]
                if (len(rows) == 2 and all(" active=0 " in row for row in rows) and final["fd"] < peak["fd"] // 2):
                    break
                await asyncio.sleep(.05)
        tail, _ = await hold(original, target, 24)
        await close_all(tail)
        await settle(proxy.pid, final)
        report(mode="generations", peak=peak, final=final, idle=idle,
               generations=3, concurrently_verified=len(all_clients))


async def main(args):
    origin = await asyncio.start_server(echo, "127.0.0.1", backlog=1024)
    command = ["taskset", "-c", args.proxy_cpus, args.binary] if args.proxy_cpus else [args.binary]
    with tempfile.TemporaryDirectory(prefix="nexus-capacity-faults-") as directory:
        root = Path(directory)
        async with origin:
            target = origin.sockets[0].getsockname()[1]
            async with asyncio.timeout(30):
                if args.mode == "fd":
                    await fd_pressure(command, target, root, args.fd_limit)
                elif args.mode == "memory":
                    await memory_limit(command, target, root, args.memory_mib, args.sessions)
                else:
                    await generations(args.binary, command, target, root)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda value: str(Path(value).resolve(strict=True)))
    parser.add_argument("mode", choices=("fd", "memory", "generations"))
    parser.add_argument("--proxy-cpus")
    parser.add_argument("--fd-limit", type=int, default=192)
    parser.add_argument("--memory-mib", type=int, default=160)
    parser.add_argument("--sessions", type=int, default=256)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < 4096:
        resource.setrlimit(resource.RLIMIT_NOFILE, (4096, hard))
    asyncio.run(main(parser.parse_args()))
