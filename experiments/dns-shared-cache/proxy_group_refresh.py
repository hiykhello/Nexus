"""Test experimental shared refresh through two SOCKS and two SS UDP inbounds."""
import base64
import json
import os
import pathlib
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
stop_owner = sys.argv[2] if len(sys.argv) > 2 else "udp"
if stop_owner not in ("tcp", "udp"):
    raise ValueError("expected tcp or udp for the pending refresh owner")
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")


def exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def read_line(proc):
    if not select.select([proc.stdout], [], [], 10)[0]:
        raise RuntimeError("fixture response timeout")
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError(f"fixture exited {proc.poll()}: {proc.stderr.read()!r}")
    return tuple(map(int, line.split()))


class DnsPeer:
    def __init__(self, address, ttl):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.address, self.ttl = address, ttl
        self.condition = threading.Condition()
        self.queries, self.pending, self.errors = [], [], []
        self.hold = False
        self.stopping = False
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def respond(self, query, peer, address, ttl):
        response = bytearray(query)
        response[2:4] = b"\x81\x80"
        if query[-4:-2] == b"\x00\x01":
            response[7] = 1
            response.extend(b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!IH", ttl, 4) + socket.inet_aton(address))
        else:
            response[9] = 1
            response.extend(b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18"
                            b"\xc0\x0c\xc0\x0c" + bytes(16) + struct.pack("!I", 60))
        self.socket.sendto(response, peer)

    def run(self):
        try:
            while not self.stopping:
                try:
                    query, peer = self.socket.recvfrom(4096)
                except TimeoutError:
                    continue
                if query[12:-4].lower() != b"\x06shared\x07example\x04test\x00" or query[-4:-2] not in (b"\x00\x01", b"\x00\x1c"):
                    raise RuntimeError(f"unexpected DNS query: {query!r}")
                with self.condition:
                    kind = query[-4:-2]
                    self.queries.append(kind)
                    held = self.hold and kind == b"\x00\x01"
                    if held:
                        self.pending.append((query, peer))
                    address, ttl = self.address, self.ttl
                    self.condition.notify_all()
                if not held:
                    self.respond(query, peer, address, ttl)
        except Exception as error:
            with self.condition:
                self.errors.append(error)
                self.condition.notify_all()

    def hold_answers(self):
        with self.condition:
            self.hold = True

    def wait_pending(self, count):
        deadline = time.monotonic() + 5
        with self.condition:
            while len(self.pending) < count and not self.errors:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("refresh did not reach DNS peer")
                self.condition.wait(remaining)
            if self.errors:
                raise self.errors[0]

    def release(self, address, ttl):
        with self.condition:
            pending, self.pending = self.pending, []
            self.address, self.ttl, self.hold = address, ttl, False
        for query, peer in pending:
            self.respond(query, peer, address, ttl)

    def counts(self):
        with self.condition:
            return self.queries.count(b"\x00\x01"), self.queries.count(b"\x00\x1c"), len(self.pending)

    def close(self):
        self.stopping = True
        self.thread.join(timeout=3)
        self.socket.close()
        if self.thread.is_alive() or self.errors:
            raise RuntimeError(f"DNS peer failed: {self.errors!r}")


class Origins:
    def __init__(self):
        self.sockets, self.handlers, self.errors = [], [], []
        self.stop = threading.Event()
        port = 0
        for label in range(1, 4):
            address = f"127.0.0.{label}"
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                sock = socket.socket(socket.AF_INET, kind)
                sock.bind((address, port))
                if not port:
                    port = sock.getsockname()[1]
                if kind == socket.SOCK_STREAM:
                    sock.listen(64)
                self.sockets.append((sock, kind, bytes([label])))
        self.port = port
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def handle(self, sock, label):
        try:
            with sock:
                sock.settimeout(5)
                data = exact(sock, 4)
                sock.sendall(label + data)
        except Exception as error:
            self.errors.append(error)

    def run(self):
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([entry[0] for entry in self.sockets], [], [], .1)
                for sock in ready:
                    _, kind, label = next(entry for entry in self.sockets if entry[0] is sock)
                    if kind == socket.SOCK_STREAM:
                        conn, _ = sock.accept()
                        thread = threading.Thread(target=self.handle, args=(conn, label))
                        self.handlers.append(thread)
                        thread.start()
                    else:
                        data, peer = sock.recvfrom(65535)
                        sock.sendto(label + data, peer)
        except Exception as error:
            self.errors.append(error)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=3)
        for sock, _, _ in self.sockets:
            sock.close()
        for thread in self.handlers:
            thread.join(timeout=5)
        if self.thread.is_alive() or any(thread.is_alive() for thread in self.handlers) or self.errors:
            raise RuntimeError(f"origin failed: {self.errors!r}")


def tcp_exchange(port, target):
    name = b"shared.example.test"
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        client.settimeout(5)
        client.sendall(b"\x05\x01\x00")
        if exact(client, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS greeting failed")
        client.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", target))
        if exact(client, 10)[:3] != b"\x05\x00\x00":
            raise RuntimeError("SOCKS connect failed")
        client.sendall(b"ping")
        reply = exact(client, 5)
        if reply[1:] != b"ping":
            raise RuntimeError("wrong TCP payload")
        return reply[0]


def associate(port):
    deadline = time.monotonic() + 5
    while True:
        try:
            tcp = socket.create_connection(("127.0.0.1", port), timeout=.2)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.02)
    tcp.settimeout(5)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(5)
    tcp.sendall(b"\x05\x01\x00")
    if exact(tcp, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS UDP greeting failed")
    tcp.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.getsockname()[1]))
    if exact(tcp, 4) != b"\x05\x00\x00\x01":
        raise RuntimeError("SOCKS UDP association failed")
    endpoint = ("127.0.0.1", struct.unpack("!H", exact(tcp, 6)[4:])[0])
    return tcp, udp, endpoint


def udp_exchange(client, target, token):
    _, udp, endpoint = client
    name = b"shared.example.test"
    udp.sendto(b"\x00\x00\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", target) + token, endpoint)
    reply, _ = udp.recvfrom(65535)
    if not reply.endswith(token) or len(reply) < len(token) + 1:
        raise RuntimeError(f"wrong UDP payload: {reply!r}")
    return reply[-len(token) - 1]


def expect(label, value):
    if value != label:
        raise RuntimeError(f"wrong destination: expected {label}, received {value}")


peers = [DnsPeer("127.0.0.1", 60), DnsPeer("127.0.0.1", 3),
         DnsPeer("127.0.0.1", 60), DnsPeer("127.0.0.3", 60)]
old_root, old_leaf, new_root, new_leaf = peers
origins = Origins()
udp_ports = []
while len(udp_ports) < 2:
    port = free_port(socket.SOCK_DGRAM)
    if port not in udp_ports:
        udp_ports.append(port)
env = dict(os.environ, NEXUS_TEST_DNS_OPTIMISTIC="1")
proc = subprocess.Popen([fixture, str(old_root.port), str(old_leaf.port), *map(str, udp_ports)],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, env=env)
boxes, clients = [], []
try:
    ports = read_line(proc)
    if len(ports) != 2:
        raise RuntimeError(f"bad fixture ports: {ports!r}")
    with tempfile.TemporaryDirectory(prefix="nexus-group-refresh-") as directory:
        for index, port in enumerate(udp_ports):
            socks_port = free_port()
            key = bytes(range(index * 16, (index + 1) * 16))
            config = {"log": {"level": "warn"},
                      "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
                      "outbounds": [{"type": "shadowsocks", "tag": "edge", "server": "127.0.0.1", "server_port": port,
                                     "method": "2022-blake3-aes-128-gcm", "password": base64.b64encode(key).decode()}],
                      "route": {"final": "edge"}}
            path = pathlib.Path(directory) / f"client-{index}.json"
            path.write_text(json.dumps(config))
            boxes.append(subprocess.Popen(["sing-box", "run", "-c", path], stderr=subprocess.PIPE))
            clients.append(associate(socks_port))

        for port in ports:
            expect(1, tcp_exchange(port, origins.port))
        for i in range(2):
            expect(1, udp_exchange(clients[i], origins.port, f"warm-{i}".encode()))
        if old_root.counts() != (1, 1, 0) or old_leaf.counts() != (1, 1, 0):
            raise RuntimeError(f"warm cache did not share views: {old_root.counts()}, {old_leaf.counts()}")

        old_leaf.hold_answers()
        time.sleep(2.25)
        barrier = threading.Barrier(5)
        outcomes, failures = [None] * 4, []
        def stale_request(index):
            try:
                barrier.wait(timeout=5)
                outcomes[index] = (tcp_exchange(ports[index], origins.port) if index < 2 else
                                   udp_exchange(clients[index - 2], origins.port, f"stale-{index}".encode()))
            except Exception as error:
                failures.append(error)
        workers = [threading.Thread(target=stale_request, args=(index,)) for index in range(4)]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=5)
        for worker in workers:
            worker.join(timeout=6)
        if any(worker.is_alive() for worker in workers) or failures or outcomes != [1] * 4:
            raise RuntimeError(f"concurrent stale requests failed: {outcomes!r}, {failures!r}")
        old_leaf.wait_pending(1)
        time.sleep(.1)
        if old_leaf.counts() != (2, 1, 1):
            raise RuntimeError(f"same-key refresh was not shared: {old_leaf.counts()}")
        old_leaf.release("127.0.0.2", 3)
        deadline = time.monotonic() + 3
        while tcp_exchange(ports[0], origins.port) != 2:
            if time.monotonic() >= deadline:
                raise RuntimeError("refreshed answer was not published")
            time.sleep(.02)
        for port in ports:
            expect(2, tcp_exchange(port, origins.port))
        for i in range(2):
            expect(2, udp_exchange(clients[i], origins.port, f"fresh-{i}".encode()))
        if old_leaf.counts() != (2, 1, 0):
            raise RuntimeError(f"unexpected DNS after refresh: {old_leaf.counts()}")

        old_leaf.hold_answers()
        time.sleep(2.25)
        if stop_owner == "udp":
            expect(2, udp_exchange(clients[1], origins.port, b"before-restart"))
        else:
            expect(2, tcp_exchange(ports[0], origins.port))
        old_leaf.wait_pending(1)
        if stop_owner == "udp":
            expect(2, tcp_exchange(ports[1], origins.port))
        else:
            expect(2, udp_exchange(clients[1], origins.port, b"other-before-restart"))
        if old_leaf.counts() != (3, 1, 1):
            raise RuntimeError(f"second refresh was not shared: {old_leaf.counts()}")
        proc.stdin.write(f"restart {new_root.port} {new_leaf.port}\n".encode())
        read_line(proc)  # Old workers have stopped and their shared budget is drained.
        ports = read_line(proc)
        if len(ports) != 2:
            raise RuntimeError(f"bad replacement ports: {ports!r}")
        old_leaf.release("127.0.0.1", 60)
        for i in range(2):
            expect(3, udp_exchange(clients[i], origins.port, f"new-{i}".encode()))
        for port in ports:
            expect(3, tcp_exchange(port, origins.port))
        if new_root.counts() != (1, 1, 0) or new_leaf.counts() != (1, 1, 0):
            raise RuntimeError(f"replacement view did not share DNS: {new_root.counts()}, {new_leaf.counts()}")

        proc.stdin.write(b"stop\n")
        read_line(proc)
        if proc.wait(timeout=5):
            raise RuntimeError(f"fixture failed: {proc.stderr.read()!r}")
finally:
    for tcp, udp, _ in clients:
        tcp.close()
        udp.close()
    for box in boxes:
        if box.poll() is None:
            box.terminate()
        box.communicate(timeout=3)
    if proc.poll() is None:
        proc.kill()
        proc.communicate(timeout=3)
    origins.close()
    for peer in peers:
        peer.close()
print(f"experimental shared refresh across SOCKS, SS UDP and replacement passed (pending {stop_owner} owner)")
