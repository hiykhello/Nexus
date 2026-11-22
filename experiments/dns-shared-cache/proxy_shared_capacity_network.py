#!/usr/bin/env python3
"""Real SOCKS, DNS and origin checks for shared capacity and group reclaim."""
import argparse
import asyncio
import collections
import pathlib
import struct

from proxy_bench import Dns, Origin, request


class TrackedDns(Dns):
    def __init__(self):
        super().__init__(600)
        self.per_name = collections.Counter()

    def datagram_received(self, data, peer):
        try:
            labels, position = [], 12
            while data[position]:
                length = data[position]
                labels.append(data[position + 1:position + 1 + length].decode("ascii").lower())
                position += length + 1
            qtype = struct.unpack_from("!H", data, position + 1)[0]
            self.per_name[(".".join(labels), qtype)] += 1
        except (IndexError, UnicodeError, struct.error) as error:
            self.errors.append(repr(error))
        super().datagram_received(data, peer)

    def queries(self, name):
        return self.per_name[(name, 1)] + self.per_name[(name, 28)]


async def command(process, value):
    process.stdin.write((value + "\n").encode())
    await process.stdin.drain()
    line = await asyncio.wait_for(process.stdout.readline(), 10)
    if not line:
        raise RuntimeError(f"fixture exited: {(await process.stderr.read()).decode(errors='replace')}")
    return line.decode().split()


async def run_case(binary, mode, count, capacity, test):
    loop = asyncio.get_running_loop()
    dns = TrackedDns()
    transport, _ = await loop.create_datagram_endpoint(lambda: dns, local_addr=("127.0.0.1", 0))
    origin = Origin()
    listener = await asyncio.start_server(origin.handle, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            str(binary), str(transport.get_extra_info("sockname")[1]), str(count), str(capacity), "2",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        ready = (await asyncio.wait_for(process.stdout.readline(), 10)).decode().split()
        if len(ready) != count + 3 or ready[:2] != ["ready", str(count)] or ready[-1] != mode:
            raise RuntimeError(f"unexpected fixture startup: {ready!r}")
        ports = list(map(int, ready[2:-1]))
        await test(process, ports, port, dns)
        if dns.errors or origin.errors:
            raise RuntimeError(f"network peer errors: {dns.errors!r}, {origin.errors!r}")
        reply = await command(process, "stop")
        if reply != ["stopped"] or await asyncio.wait_for(process.wait(), 10) != 0:
            raise RuntimeError("fixture failed to stop")
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        listener.close()
        await listener.wait_closed()
        transport.close()


async def one_group(process, ports, origin, dns, baseline=False):
    names = [f"single-{index:04}.example.test" for index in range(600)]
    for index, name in enumerate(names):
        await request(ports[0], origin, name, index, False, 5)
    stats = await command(process, "stats")
    if not baseline and (len(stats) != 3 or stats[0] != "stats" or int(stats[1]) <= 1024):
        raise RuntimeError(f"single group did not retain more than 1024 members: {stats!r}")
    if dns.queries(names[0]) != 2:
        raise RuntimeError("initial A/AAAA pair was not resolved once")
    before = dns.queries(names[0])
    await request(ports[0], origin, names[0], 10001, False, 5)
    after = dns.queries(names[0])
    if (after == before) == baseline:
        raise RuntimeError(f"unexpected first-key retention for {'baseline' if baseline else 'group'}: {before} -> {after}")
    print(f"one group: {stats}, first key upstream queries {before} -> {after}", flush=True)


async def two_groups(process, ports, origin, dns):
    first = [f"first-{index:03}.example.test" for index in range(48)]
    second = [f"second-{index:03}.example.test" for index in range(24)]
    later = [f"later-{index:03}.example.test" for index in range(24)]
    for index, name in enumerate(first):
        await request(ports[0], origin, name, index, False, 5)
    if (await command(process, "stats"))[1:3] != ["96", "0"]:
        raise RuntimeError("first group did not borrow the empty group's capacity")
    for index, name in enumerate(second):
        await request(ports[1], origin, name, 1000 + index, False, 5)
    if (await command(process, "stats"))[1:3] != ["48", "48"]:
        raise RuntimeError("second group did not reclaim its share")
    before = dns.queries(first[0])
    await request(ports[0], origin, first[0], 2001, False, 5)
    if dns.queries(first[0]) <= before:
        raise RuntimeError("reclaimed first-group entries unexpectedly hit")
    for index, name in enumerate(later):
        await request(ports[0], origin, name, 3000 + index, False, 5)
    before = dns.queries(second[0])
    await request(ports[1], origin, second[0], 4001, False, 5)
    if dns.queries(second[0]) != before:
        raise RuntimeError("first group displaced the second group's share")
    before = dns.queries(later[-1])
    await request(ports[1], origin, later[-1], 4002, False, 5)
    if dns.queries(later[-1]) != before:
        raise RuntimeError("compatible groups did not share an answer")
    negative = "miss-cross.example.test"
    await request(ports[0], origin, negative, 5000, True, 5)
    before = dns.queries(negative)
    await request(ports[1], origin, negative, 5001, True, 5)
    if before != 1 or dns.queries(negative) != before:
        raise RuntimeError("compatible groups did not share the negative answer")
    stats = await command(process, "stats")
    if stats[1:3] != ["48", "48"]:
        raise RuntimeError(f"group counts changed after replacements: {stats!r}")
    print(f"two groups: borrowed 96, then 48/48 protected; shared positive and negative: {stats}", flush=True)


async def main(args):
    await run_case(args.group, "group", 1, 2048, one_group)
    await run_case(args.group, "group", 2, 96, two_groups)
    if args.baseline:
        async def baseline_case(process, ports, origin, dns):
            await one_group(process, ports, origin, dns, baseline=True)
        await run_case(args.baseline, "baseline", 1, 2048, baseline_case)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("group", type=pathlib.Path)
    parser.add_argument("--baseline", type=pathlib.Path)
    arguments = parser.parse_args()
    asyncio.run(main(arguments))
