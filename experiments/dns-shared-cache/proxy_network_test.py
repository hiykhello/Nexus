#!/usr/bin/env python3
"""Exercise concurrent readers, pending DNS, cancellation, restart and stop."""
import asyncio
import collections
import pathlib
import socket
import struct
import sys


class Dns(asyncio.DatagramProtocol):
    def __init__(self, address):
        self.address = socket.inet_aton(address)
        self.hold = set()
        self.pending = collections.defaultdict(list)
        self.counts = collections.Counter()
        self.changed = asyncio.Event()
        self.errors = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, query, peer):
        try:
            labels, pos = [], 12
            while query[pos]:
                length = query[pos]
                if length > 63:
                    raise ValueError("invalid label")
                labels.append(query[pos + 1:pos + length + 1].decode("ascii").lower())
                pos += length + 1
            pos += 1
            qtype, qclass = struct.unpack_from("!HH", query, pos)
            if qclass != 1 or qtype not in (1, 28) or pos + 4 != len(query):
                raise ValueError("invalid question")
            name = ".".join(labels)
            self.counts[(name, qtype)] += 1
            if qtype == 1 and name in self.hold:
                self.pending[name].append((query, peer, qtype))
                self.changed.set()
            else:
                self.reply(query, peer, qtype)
        except Exception as error:
            self.errors.append(repr(error))

    def reply(self, query, peer, qtype):
        question = query[12:]
        if qtype == 1:
            answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!IH", 120, 4) + self.address
            response = query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer
        else:
            soa = b"\xc0\x0c\x00\x06\x00\x01" + struct.pack("!IH", 120, 24)
            soa += b"\xc0\x0c\xc0\x0c" + struct.pack("!IIIII", 1, 1, 1, 1, 120)
            response = query[:2] + b"\x81\x80\x00\x01\x00\x00\x00\x01\x00\x00" + question + soa
        self.transport.sendto(response, peer)

    async def wait_pending(self, name, count):
        async def wait():
            while len(self.pending[name]) < count:
                self.changed.clear()
                await self.changed.wait()
        await asyncio.wait_for(wait(), 5)

    def release(self, name):
        pending = self.pending.pop(name)
        for query, peer, qtype in pending:
            self.reply(query, peer, qtype)
        return {peer[1] for _, peer, _ in pending}


class Origins:
    def __init__(self):
        self.counts = collections.Counter()
        self.tasks = set()

    async def serve(self, reader, writer, label):
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            await reader.readexactly(1)
            writer.write(label.encode())
            await writer.drain()
            self.counts[label] += 1
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            self.tasks.discard(task)


async def open_request(proxy_port, origin_port, name, writers):
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writers.append(writer)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    if await asyncio.wait_for(reader.readexactly(2), 5) != b"\x05\x00":
        raise RuntimeError("bad greeting")
    domain = name.encode()
    writer.write(b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + struct.pack("!H", origin_port))
    await writer.drain()
    return reader, writer


async def finish_request(client, label):
    reader, writer = client
    reply = await asyncio.wait_for(reader.readexactly(10), 5)
    if reply[:3] != b"\x05\x00\x00":
        raise RuntimeError(f"bad SOCKS reply {reply.hex()}")
    writer.write(b"x")
    await writer.drain()
    if await asyncio.wait_for(reader.readexactly(1), 5) != label.encode():
        raise RuntimeError("connection reached the wrong origin")
    writer.close()
    await writer.wait_closed()


async def reset(client):
    _, writer = client
    writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    writer.close()
    try:
        await writer.wait_closed()
    except ConnectionError:
        pass


async def expect_closed(client):
    reader, writer = client
    try:
        data = await asyncio.wait_for(reader.read(1), 5)
        if data:
            raise RuntimeError(f"pending session returned data after stop: {data!r}")
    except ConnectionError:
        pass
    writer.close()
    try:
        await writer.wait_closed()
    except ConnectionError:
        pass


async def expect_udp_closed(ports):
    async def wait():
        while True:
            rows = pathlib.Path("/proc/net/udp").read_text().splitlines()[1:]
            open_ports = {int(row.split()[1].split(":")[1], 16) for row in rows}
            if not ports.intersection(open_ports):
                return
            await asyncio.sleep(0.02)
    await asyncio.wait_for(wait(), 5)


async def main(fixture, mode):
    loop = asyncio.get_running_loop()
    old_dns, new_dns = Dns("127.0.0.1"), Dns("127.0.0.2")
    old_transport, _ = await loop.create_datagram_endpoint(lambda: old_dns, local_addr=("127.0.0.1", 0))
    new_transport, _ = await loop.create_datagram_endpoint(lambda: new_dns, local_addr=("127.0.0.1", 0))
    origins = Origins()
    first = await asyncio.start_server(lambda r, w: origins.serve(r, w, "A"), "127.0.0.1", 0, backlog=128)
    origin_port = first.sockets[0].getsockname()[1]
    second = await asyncio.start_server(lambda r, w: origins.serve(r, w, "B"), "127.0.0.2", origin_port, backlog=128)
    proc = await asyncio.create_subprocess_exec(str(fixture), str(old_transport.get_extra_info("sockname")[1]), "4",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    writers = []
    try:
        ready = (await asyncio.wait_for(proc.stdout.readline(), 5)).decode().split()
        if len(ready) != 3 or ready[0] != "ready" or ready[2] != mode:
            raise RuntimeError(f"invalid fixture response {ready}")
        port = int(ready[1])

        warm = await asyncio.gather(*(open_request(port, origin_port, "warm.example.test", writers) for _ in range(32)))
        await asyncio.gather(*(finish_request(client, "A") for client in warm))

        name = "pending.example.test"
        old_dns.hold.add(name)
        clients = await asyncio.gather(*(open_request(port, origin_port, name, writers) for _ in range(16)))
        await old_dns.wait_pending(name, 16)
        # At least four sessions share a worker; paused queries must not hold its reader.
        concurrent = await asyncio.gather(*(open_request(port, origin_port, "warm.example.test", writers) for _ in range(32)))
        await asyncio.gather(*(finish_request(client, "A") for client in concurrent))
        await asyncio.gather(*(reset(client) for client in clients[:8]))
        await asyncio.sleep(0.1)
        pending_ports = old_dns.release(name)
        await asyncio.gather(*(finish_request(client, "A") for client in clients[8:]))
        await expect_udp_closed(pending_ports)

        name = "switch.example.test"
        old_dns.hold.add(name)
        switching = await asyncio.gather(*(open_request(port, origin_port, name, writers) for _ in range(16)))
        await old_dns.wait_pending(name, 16)
        old_ports = {peer[1] for _, peer, _ in old_dns.pending[name]}
        proc.stdin.write(f"restart {new_transport.get_extra_info('sockname')[1]}\n".encode())
        await proc.stdin.drain()
        ready = (await asyncio.wait_for(proc.stdout.readline(), 5)).decode().split()
        if len(ready) != 4 or ready[:3] != ["ready", str(port), mode]:
            raise RuntimeError(f"restart failed: {ready}")
        await asyncio.gather(*(expect_closed(client) for client in switching))
        await expect_udp_closed(old_ports)
        old_dns.release(name)  # Late old-view replies must not populate the new cache.
        changed = await asyncio.gather(*(open_request(port, origin_port, name, writers) for _ in range(16)))
        await asyncio.gather(*(finish_request(client, "B") for client in changed))
        if not new_dns.counts[(name, 1)]:
            raise RuntimeError("new DNS view was not queried")

        name = "stop.example.test"
        new_dns.hold.add(name)
        stopping = await asyncio.gather(*(open_request(port, origin_port, name, writers) for _ in range(16)))
        await new_dns.wait_pending(name, 16)
        stop_ports = {peer[1] for _, peer, _ in new_dns.pending[name]}
        proc.stdin.write(b"stop\n")
        await proc.stdin.drain()
        stopped = (await asyncio.wait_for(proc.stdout.readline(), 5)).decode().split()
        if len(stopped) != 2 or stopped[0] != "stopped":
            raise RuntimeError(f"stop failed: {stopped}")
        await asyncio.gather(*(expect_closed(client) for client in stopping))
        await expect_udp_closed(stop_ports)
        new_dns.release(name)
        await asyncio.wait_for(proc.wait(), 5)
        stderr = (await proc.stderr.read()).decode()
        if proc.returncode or old_dns.errors or new_dns.errors:
            raise RuntimeError(f"fixture or DNS failure: {proc.returncode} {stderr} {old_dns.errors} {new_dns.errors}")
        print(f"{mode}: concurrent lookups, RST cancellation, DNS-view restart, late replies, and pending stop passed")
    finally:
        for writer in writers:
            writer.close()
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        old_transport.close()
        new_transport.close()
        first.close()
        second.close()
        await first.wait_closed()
        await second.wait_closed()
        if origins.tasks:
            await asyncio.gather(*origins.tasks, return_exceptions=True)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[2] not in ("per-worker", "shared", "snapshot", "group"):
        raise SystemExit("usage: proxy_network_test.py fixture per-worker|shared|snapshot|group")
    asyncio.run(main(pathlib.Path(sys.argv[1]).resolve(strict=True), sys.argv[2]))
