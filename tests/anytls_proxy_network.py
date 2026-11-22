#!/usr/bin/env python3
"""AnyTLS production Server API: worker pools, restart, detour and UoT v2."""
import argparse
import contextlib
import json
import pathlib
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time

from anytls_network import Origin
from detour_network import running
from dns_rule_support import Echo, exact, free_port, udp_client


class CountedRelay:
    def __init__(self, target):
        self.target, self.accepted, self.closed = target, 0, 0
        self.stop, self.condition, self.peers, self.errors = threading.Event(), threading.Condition(), [], []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]

    def peer(self, incoming):
        try:
            with incoming, socket.create_connection(("127.0.0.1", self.target), timeout=3) as outgoing:
                incoming.setblocking(False)
                outgoing.setblocking(False)
                while not self.stop.is_set():
                    ready, _, _ = select.select([incoming, outgoing], [], [], .1)
                    for source in ready:
                        data = source.recv(65535)
                        if not data:
                            return
                        destination = outgoing if source is incoming else incoming
                        view = memoryview(data)
                        while view:
                            if not select.select([], [destination], [], 3)[1]:
                                raise TimeoutError("relay write stalled")
                            view = view[destination.send(view):]
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as error:
            self.errors.append(error)
        finally:
            with self.condition:
                self.closed += 1
                self.condition.notify_all()

    def serve(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            with self.condition:
                self.accepted += 1
                self.condition.notify_all()
            peer = threading.Thread(target=self.peer, args=(client,))
            self.peers.append(peer)
            peer.start()

    def wait(self, accepted, closed):
        with self.condition:
            if not self.condition.wait_for(lambda: self.accepted == accepted and self.closed == closed, timeout=5):
                raise RuntimeError(f"TLS pool connections accepted/closed={self.accepted}/{self.closed}; expected={accepted}/{closed}")
        if self.errors:
            raise RuntimeError(self.errors)

    def __enter__(self):
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()
        return self

    def __exit__(self, kind, *_):
        self.stop.set()
        self.thread.join(2)
        for peer in self.peers:
            peer.join(4)
        self.listener.close()
        if kind is None and (self.errors or any(peer.is_alive() for peer in self.peers)):
            raise RuntimeError(f"relay did not drain: {self.errors}")


def port_line(process):
    if not select.select([process.stdout], [], [], 8)[0]:
        raise RuntimeError(f"AnyTLS Server API did not start; exit={process.poll()}")
    value = process.stdout.readline().strip()
    if not value.isdigit():
        raise RuntimeError(f"invalid API listener: {value!r}, {process.communicate(timeout=3)!r}")
    return int(value)


@contextlib.contextmanager
def proxy(fixture, root, peer, workers, lower=None):
    command = [fixture, str(peer), str(root / "password"), str(root / "cert"), str(workers), "1", "1"]
    if lower:
        command.append(str(lower))
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    try:
        yield process, port_line(process)
    finally:
        if process.poll() is None:
            try:
                stdout, stderr = process.communicate(b"x\n", timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=3)
                raise RuntimeError(f"AnyTLS Server::stop did not drain: {stdout!r}, {stderr!r}")
            if process.returncode:
                raise RuntimeError(f"AnyTLS proxy failed: {process.returncode}, {stdout!r}, {stderr!r}")


def begin(front, target):
    client = socket.create_connection(("127.0.0.1", front), timeout=5)
    client.sendall(b"\x05\x01\x00")
    if exact(client, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting")
    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target))
    return client


def reply(client):
    header = exact(client, 4)
    if header[1] or header[3] not in (1, 4):
        raise RuntimeError(f"AnyTLS SOCKS connect failed: {header!r}")
    exact(client, 6 if header[3] == 1 else 18)


def payload(client, size=512 * 1024):
    data, errors = bytes(range(256)) * (size // 256), []

    def write():
        try:
            client.sendall(data)
        except Exception as error:
            errors.append(error)

    writer = threading.Thread(target=write)
    writer.start()
    if exact(client, len(data)) != data:
        raise RuntimeError("AnyTLS production data mismatch")
    writer.join(5)
    if writer.is_alive() or errors:
        raise RuntimeError(f"AnyTLS production write failed: {errors}")


def targets_closed(origin, count):
    with origin.condition:
        if not origin.condition.wait_for(lambda: origin.closed >= count, timeout=5) or origin.errors:
            raise RuntimeError(f"AnyTLS stream targets did not close: {origin.closed}, {origin.errors}")


def check(fixture, root, workers, layered):
    front, lower = free_port(), free_port()
    tls = {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")}
    config = root / "server.json"
    config.write_text(json.dumps({"log": {"level": "warn"}, "inbounds": [
        {"type": "anytls", "listen": "127.0.0.1", "listen_port": front, "users": [{"password": "anytls-network-secret"}], "tls": tls},
        {"type": "trojan", "listen": "127.0.0.1", "listen_port": lower, "users": [{"password": "anytls-network-secret"}], "tls": tls}],
        "outbounds": [{"type": "direct"}]}))
    with running(["sing-box", "run", "-c", config], front, root / "box.log"), CountedRelay(front) as relay:
        with proxy(fixture, root, relay.port, workers, lower if layered else None) as (process, socks), Origin() as origin:
            relay.wait(workers, 0)
            if origin.closed or origin.peers:
                raise RuntimeError("prewarming reached a business destination")
            for index in range(3):
                with begin(socks, origin.port) as client:
                    reply(client)
                    payload(client)
                targets_closed(origin, index + 1)
            relay.wait(workers, 0)
            process.stdin.write(b"r\n")
            process.stdin.flush()
            socks = port_line(process)
            relay.wait(2 * workers, workers)
            with begin(socks, origin.port) as client:
                reply(client)
                payload(client)
            targets_closed(origin, 4)
            if workers == 1:
                with begin(socks, origin.port) as first:
                    reply(first)
                    with begin(socks, origin.port) as queued:
                        if select.select([queued], [], [], .1)[0]:
                            raise RuntimeError("full pool did not hold the queued dial")
                        payload(first, 16384)
                        first.close()
                        reply(queued)
                        payload(queued, 16384)
                targets_closed(origin, 6)
            with Echo() as udp, udp_client(socks) as (client, remote):
                header = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.port)
                for data in (b"AnyTLS-UoT", b"", bytes(range(256)) * 32):
                    client.sendto(header + data, remote)
                    try:
                        response = client.recvfrom(65535)[0]
                    except TimeoutError as error:
                        raise RuntimeError(f"AnyTLS UoT timed out for {len(data)} bytes; origin received={list(map(len, udp.received))}; TLS={relay.accepted}/{relay.closed}") from error
                    if response != header + data:
                        raise RuntimeError("AnyTLS UoT v2 reply mismatch")
            relay.wait(2 * workers, workers)
        relay.wait(2 * workers, 2 * workers)
    print(f"AnyTLS Server API pool reuse/prewarm/restart/stop/UoT passed: workers={workers}, layered={layered}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    args = parser.parse_args()
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], capture_output=True, text=True, check=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
    with tempfile.TemporaryDirectory(prefix="nexus-anytls-proxy-") as directory:
        root = pathlib.Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key", "-out", root / "cert",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root / "password").write_text("anytls-network-secret\n")
        for name in ("key", "password"):
            (root / name).chmod(0o600)
        for layered in (False, True):
            for workers in (1, 2):
                check(args.fixture.resolve(), root, workers, layered)


if __name__ == "__main__":
    main()
