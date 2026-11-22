#!/usr/bin/env python3
"""Production Upgrade relay kernel backpressure, recovery, reset and active stop."""
import argparse
import contextlib
import hashlib
import pathlib
import select
import socket
import struct
import tempfile
import threading
import time

from dns_rule_support import DnsPeer, exact, free_port, nexus_process, proxy_client
from httpupgrade_cli_network import (ALICE, UUID, begin, certificates, client_config,
                                     go_outbound, server_config, sing_server)

BLOCK = bytes(range(256)) * 256
EXPECTED = BLOCK + BLOCK
AMOUNT = 64 * 1024 * 1024


class Writer:
    def __init__(self, source):
        self.source, self.count, self.error = source, 0, None
        self.done, self.stopping = threading.Event(), threading.Event()
        self.worker = threading.Thread(target=self.run)

    def run(self):
        try:
            while self.count < AMOUNT:
                if self.stopping.is_set():
                    raise RuntimeError("test sender canceled")
                if not select.select([], [self.source], [], .1)[1]:
                    continue
                offset = self.count % len(BLOCK)
                try:
                    size = self.source.send(memoryview(BLOCK)[offset:])
                except BlockingIOError:
                    continue
                if not size:
                    raise RuntimeError("production Upgrade sender made no progress")
                self.count += size
            self.source.shutdown(socket.SHUT_WR)
        except Exception as error:
            self.error = error
        finally:
            self.done.set()

    def start(self):
        self.source.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        self.source.setblocking(False)
        self.worker.start()

    def stalled(self):
        limit = time.monotonic() + 8
        previous, stable = self.count, time.monotonic()
        while time.monotonic() < limit:
            if self.done.is_set():
                raise RuntimeError(f"production Upgrade sender did not reach backpressure: {self.count}, {self.error}")
            if previous != self.count:
                previous, stable = self.count, time.monotonic()
            if previous and time.monotonic() - stable >= 1.1:
                return previous
            time.sleep(.01)
        raise RuntimeError(f"production Upgrade sender never stabilized: bytes={self.count}")

    def finish(self, successful):
        self.worker.join(6)
        if self.worker.is_alive() or (successful and (self.error or self.count != AMOUNT)):
            raise RuntimeError(f"production Upgrade sender failed to drain: alive={self.worker.is_alive()}, bytes={self.count}, error={self.error}")

    def cancel(self):
        self.stopping.set()
        self.worker.join(3)


def receive(receiver):
    receiver.settimeout(20)
    offset, digest = 0, hashlib.sha256()
    while offset < AMOUNT:
        data = receiver.recv(min(65536, AMOUNT - offset))
        if not data or data != EXPECTED[offset % 256:offset % 256 + len(data)]:
            raise RuntimeError(f"production Upgrade lost/reordered backpressured data: offset={offset}, size={len(data)}")
        digest.update(data)
        offset += len(data)
    if receiver.recv(1):
        raise RuntimeError("production Upgrade sent data after the exact body and half-close")
    return digest.digest()


def drained(peer):
    peer.settimeout(5)
    size = 0
    while True:
        try:
            data = peer.recv(65536)
        except ConnectionResetError:
            break
        if not data:
            break
        size += len(data)
        if size >= AMOUNT:
            raise RuntimeError("production Upgrade cancellation forwarded the whole paused body")
    return size


@contextlib.contextmanager
def topology(binary, root, workers, role, dns):
    remote, front, lower = free_port(), free_port(), free_port()
    if role == "inbound":
        with nexus_process(binary, server_config(root, remote, workers, dns)) as process, proxy_client(root, go_outbound(root, remote)) as front:
            yield front, process
    else:
        with sing_server(root, remote, lower, dns), \
             nexus_process(binary, client_config(root, front, remote, workers, dns, lower if role == "detour" else None)) as process:
            yield front, process


def exercise(binary, root, workers, role, mode, dns):
    with socket.socket() as target:
        target.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        target.bind(("127.0.0.1", 0))
        target.listen(1)
        target.settimeout(5)
        with topology(binary, root, workers, role, dns) as (front, process), begin(front, target.getsockname()[1]) as client, target.accept()[0] as peer:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            client.settimeout(20)
            peer.settimeout(20)
            download = mode == "download"
            source, receiver = (peer, client) if download else (client, peer)
            writer = Writer(source)
            writer.start()
            try:
                paused = writer.stalled()
                if mode in ("upload", "download"):
                    digest = receive(receiver)
                    writer.finish(successful=True)
                    source.settimeout(20)
                    receiver.sendall(b"done" + digest)
                    receiver.shutdown(socket.SHUT_WR)
                    if exact(source, 36) != b"done" + digest or source.recv(1):
                        raise RuntimeError("production Upgrade reverse data after authenticated half-close was lost")
                    result = f"stable=1100ms, restored={AMOUNT} bytes"
                else:
                    if mode == "stop":
                        process.terminate()
                        if process.wait(timeout=5):
                            raise RuntimeError("production Upgrade active stop did not exit cleanly")
                    else:
                        # A TCP reset is an unambiguous failed business owner;
                        # a clean write EOF must preserve the other direction.
                        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                        client.close()
                    remaining = drained(peer)
                    writer.finish(successful=False)
                    if writer.count >= AMOUNT:
                        raise RuntimeError("production Upgrade active cancellation arrived after completion")
                    if mode != "stop" and process.poll() is not None:
                        raise RuntimeError("production Upgrade peer reset killed the listener")
                    if mode == "reset":
                        with begin(front, target.getsockname()[1]) as recovered, target.accept()[0] as later:
                            recovered.sendall(b"after-reset")
                            if exact(later, 11) != b"after-reset":
                                raise RuntimeError("production Upgrade profile/listener did not recover after reset")
                            recovered.shutdown(socket.SHUT_WR)
                            if later.recv(1):
                                raise RuntimeError("production Upgrade recovery lost upload half-close")
                            later.sendall(b"alive")
                            later.shutdown(socket.SHUT_WR)
                            if exact(recovered, 5) != b"alive" or recovered.recv(1):
                                raise RuntimeError("production Upgrade recovery lost reverse data/half-close")
                    result = f"stable=1100ms, pending={AMOUNT - paused}, drained={remaining} bytes"
            finally:
                writer.cancel()
    print(f"HTTPUpgrade CLI {role}/{mode} passed: workers={workers}, {result}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--role", choices=("all", "inbound", "outbound", "detour"), default="all")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nexus-upgrade-cli-lifecycle-") as directory, DnsPeer() as dns:
        root = pathlib.Path(directory)
        certificates(root)
        for name, value in (("uuid", UUID), ("alice", ALICE), ("password", "upgrade-lower")):
            (root / name).write_text(value + "\n")
            (root / name).chmod(0o600)
        roles = ("inbound", "outbound", "detour") if args.role == "all" else (args.role,)
        for workers in (1, 2):
            for role in roles:
                for mode in ("upload", "download", "reset", "stop"):
                    exercise(args.binary.resolve(), root, workers, role, mode, dns)


if __name__ == "__main__":
    main()
