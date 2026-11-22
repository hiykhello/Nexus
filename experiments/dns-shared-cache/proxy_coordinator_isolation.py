"""Distinct real DNS routes must not share answers or in-flight lookups."""
import pathlib
import select
import socket
import struct
import subprocess
import sys
import threading
import time

fixture = pathlib.Path(sys.argv[1]).resolve()


def exact(sock, count):
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise RuntimeError("unexpected EOF")
        result += part
    return result


class DnsPeer:
    def __init__(self, address):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.address = socket.inet_aton(address)
        self.condition = threading.Condition()
        self.release = threading.Event()
        self.stopping = False
        self.queries = []
        self.errors = []
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        try:
            while not self.stopping:
                try:
                    query, sender = self.socket.recvfrom(4096)
                except TimeoutError:
                    continue
                if query[12:] != b"\x05split\x07example\x04test\x00\x00\x01\x00\x01":
                    raise RuntimeError(f"unexpected DNS query: {query!r}")
                with self.condition:
                    self.queries.append(query)
                    self.condition.notify_all()
                if not self.release.wait(5):
                    raise RuntimeError("DNS response was not released")
                response = bytearray(query)
                response[2:4] = b"\x81\x80"
                response[7] = 1
                response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + self.address)
                self.socket.sendto(response, sender)
        except Exception as error:
            with self.condition:
                self.errors.append(error)
                self.condition.notify_all()

    def wait(self):
        deadline = time.monotonic() + 5
        with self.condition:
            while not self.queries and not self.errors:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("DNS peer did not receive its query")
                self.condition.wait(remaining)
            if self.errors:
                raise self.errors[0]

    def close(self):
        self.stopping = True
        self.release.set()
        self.thread.join(timeout=5)
        self.socket.close()
        if self.thread.is_alive() or self.errors:
            raise RuntimeError(f"DNS peer failed: {self.errors!r}")


def exchange(socks_port, origin_port, expected, payload):
    with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as client:
        client.settimeout(5)
        client.sendall(b"\x05\x01\x00")
        if exact(client, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS greeting failed")
        name = b"split.example.test"
        client.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", origin_port))
        if exact(client, 10)[:3] != b"\x05\x00\x00":
            raise RuntimeError("SOCKS connect failed")
        client.sendall(payload)
        if exact(client, len(payload) + 1) != expected + payload:
            raise RuntimeError("request reached the wrong DNS route")


peers = [DnsPeer("127.0.0.1"), DnsPeer("127.0.0.2")]
origins = []
threads = []
errors = []
stopping = threading.Event()
process = None
try:
    for address in ("127.0.0.1", "127.0.0.2"):
        origin = socket.socket()
        origin.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        origin.bind((address, origins[0].getsockname()[1] if origins else 0))
        origin.listen(16)
        origin.settimeout(.1)
        origins.append(origin)

    def serve(origin, prefix):
        try:
            while not stopping.is_set():
                try:
                    connection, _ = origin.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(5)
                    connection.sendall(prefix + exact(connection, 4))
        except Exception as error:
            errors.append(error)

    for index, origin in enumerate(origins):
        thread = threading.Thread(target=serve, args=(origin, bytes([65 + index])))
        thread.start()
        threads.append(thread)

    process = subprocess.Popen([str(fixture), *(str(peer.port) for peer in peers)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    if not select.select([process.stdout], [], [], 10)[0]:
        raise RuntimeError("fixture did not start")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError(f"fixture exited: {process.stderr.read()!r}")
    ports = tuple(map(int, line.split()))
    if len(ports) != 2:
        raise RuntimeError(f"invalid fixture ports: {line!r}")

    clients = []
    def first_request(index):
        try:
            exchange(ports[index], origins[0].getsockname()[1], bytes([65 + index]), b"init")
        except Exception as error:
            errors.append(error)
    for index in range(2):
        client = threading.Thread(target=first_request, args=(index,))
        client.start()
        clients.append(client)
    for peer in peers:
        peer.wait()
    for peer in peers:
        peer.release.set()
    for client in clients:
        client.join(timeout=8)
    if errors or any(client.is_alive() for client in clients):
        raise RuntimeError(f"initial requests failed: {errors!r}")

    for _ in range(4):
        for index in range(2):
            exchange(ports[index], origins[0].getsockname()[1], bytes([65 + index]), b"warm")
    for peer in peers:
        with peer.condition:
            if len(peer.queries) != 1:
                raise RuntimeError(f"unexpected upstream query count: {len(peer.queries)}")
    process.stdin.write(b"stop\n")
    if process.wait(timeout=5):
        raise RuntimeError(f"fixture failed: {process.stderr.read()!r}")
finally:
    if process and process.poll() is None:
        process.kill()
        process.wait(timeout=5)
    stopping.set()
    for peer in peers:
        peer.close()
    for thread in threads:
        thread.join(timeout=5)
    for origin in origins:
        origin.close()
    if errors or any(thread.is_alive() for thread in threads):
        raise RuntimeError(f"origin server failed: {errors!r}")
print("two SOCKS inbounds kept different DNS routes and cached answers isolated")
