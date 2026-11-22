"""Two real SOCKS inbounds share an experimental cache and replace its owner."""
import pathlib
import base64
import json
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import tempfile

fixture = pathlib.Path(sys.argv[1]).resolve()
options = set(sys.argv[2:])
if options - {"--udp", "--coordinated"}:
    raise ValueError("unknown group network test option")
udp_mode = "--udp" in options
coordinated = "--coordinated" in options
if udp_mode:
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError("unexpected sing-box revision")


def exact(sock, count):
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise RuntimeError("unexpected EOF")
        result += part
    return result


class DnsPeer:
    def __init__(self, address, hold_shared=False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(.1)
        self.port = self.sock.getsockname()[1]
        self.address = socket.inet_aton(address)
        self.hold_shared = hold_shared
        self.lock = threading.Condition()
        self.queries = []
        self.pending = []
        self.errors = []
        self.stopping = False
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def respond(self, query, peer):
        response = bytearray(query)
        response[2:4] = b"\x81\x80"
        if query[-4:-2] == b"\x00\x01":
            response[7] = 1
            response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + self.address)
        else:
            response[9] = 1
            response.extend(b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18"
                            b"\xc0\x0c\xc0\x0c" + bytes(16) + struct.pack("!I", 60))
        self.sock.sendto(response, peer)

    def run(self):
        try:
            while not self.stopping:
                try:
                    query, peer = self.sock.recvfrom(4096)
                except TimeoutError:
                    continue
                name, kind = query[12:-4].lower(), query[-4:-2]
                if name not in (b"\x06shared\x07example\x04test\x00", b"\x07pending\x04test\x00") or kind not in (b"\x00\x01", b"\x00\x1c"):
                    raise RuntimeError(f"unexpected DNS query {query!r}")
                with self.lock:
                    self.queries.append((name, kind))
                    hold = name.startswith(b"\x07pending") or (self.hold_shared and kind == b"\x00\x01")
                    if hold:
                        self.pending.append((query, peer))
                    self.lock.notify_all()
                if not hold:
                    self.respond(query, peer)
        except Exception as error:
            self.errors.append(error)
            with self.lock:
                self.lock.notify_all()

    def wait_pending(self, count):
        deadline = time.monotonic() + 5
        with self.lock:
            while len(self.pending) < count and not self.errors:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("DNS queries did not become pending")
                self.lock.wait(remaining)
        if self.errors:
            raise self.errors[0]

    def release(self):
        with self.lock:
            held, self.pending = self.pending, []
            self.hold_shared = False
        for query, peer in held:
            self.respond(query, peer)

    def close(self):
        self.stopping = True
        self.thread.join(timeout=3)
        self.sock.close()
        if self.thread.is_alive() or self.errors:
            raise RuntimeError(f"DNS peer failed: {self.errors!r}")


def greeting(port, name, target_port, wait=True):
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.settimeout(5)
    client.sendall(b"\x05\x01\x00")
    if exact(client, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting failed")
    client.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", target_port))
    if wait and exact(client, 10)[:3] != b"\x05\x00\x00":
        raise RuntimeError("SOCKS connect failed")
    return client


def exchange(port, origin):
    with greeting(port, b"shared.example.test", origin.getsockname()[1]) as client:
        with origin.accept()[0] as remote:
            remote.settimeout(5)
            client.sendall(b"ping")
            if exact(remote, 4) != b"ping":
                raise RuntimeError("origin payload failed")
            remote.sendall(b"pong")
            if exact(client, 4) != b"pong":
                raise RuntimeError("client payload failed")


def read_line(process):
    if not select.select([process.stdout], [], [], 10)[0]:
        raise RuntimeError("fixture response timeout")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError(f"fixture exited: {process.stderr.read()!r}")
    return tuple(map(int, line.split()))


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


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
        raise RuntimeError("UDP association greeting failed")
    tcp.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.getsockname()[1]))
    if exact(tcp, 4) != b"\x05\x00\x00\x01":
        raise RuntimeError("UDP association failed")
    endpoint = ("127.0.0.1", struct.unpack("!H", exact(tcp, 6)[4:])[0])
    return tcp, udp, endpoint


old_root, old_dns = DnsPeer("127.0.0.1"), DnsPeer("127.0.0.1")
new_root, new_dns = DnsPeer("127.0.0.1"), DnsPeer("127.0.0.2", hold_shared=True)
with socket.socket() as old_origin, socket.socket() as new_origin:
    old_origin.bind(("127.0.0.1", 0))
    new_origin.bind(("127.0.0.2", old_origin.getsockname()[1]))
    for origin in (old_origin, new_origin):
        origin.listen(32)
        origin.settimeout(5)
    udp_ports = []
    if udp_mode:
        while len(udp_ports) != 2:
            port = free_port(socket.SOCK_DGRAM)
            if port not in udp_ports:
                udp_ports.append(port)
    process = subprocess.Popen([str(fixture), str(old_root.port), str(old_dns.port), *map(str, udp_ports)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    pending, clients, boxes, udp_targets = [], [], [], []
    echo_stop = threading.Event()
    echo_errors = []
    delivered = [[], []]
    echo_thread = None
    directory = tempfile.TemporaryDirectory(prefix="nexus-group-udp-") if udp_mode else None
    try:
        ports = read_line(process)
        if udp_mode:
            for address in ("127.0.0.1", "127.0.0.2"):
                target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                target.bind((address, old_origin.getsockname()[1]))
                udp_targets.append(target)

            def echo():
                try:
                    while not echo_stop.is_set():
                        ready, _, _ = select.select(udp_targets, [], [], .1)
                        for target in ready:
                            data, peer = target.recvfrom(65535)
                            delivered[udp_targets.index(target)].append(data)
                            target.sendto(data, peer)
                except Exception as error:
                    echo_errors.append(error)

            echo_thread = threading.Thread(target=echo)
            echo_thread.start()
            for index, port in enumerate(udp_ports):
                socks_port = free_port()
                key = bytes(range(index * 16, (index + 1) * 16))
                config = {"log": {"level": "warn"},
                          "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
                          "outbounds": [{"type": "shadowsocks", "tag": "edge", "server": "127.0.0.1",
                                         "server_port": port, "method": "2022-blake3-aes-128-gcm",
                                         "password": base64.b64encode(key).decode()}],
                          "route": {"final": "edge"}}
                path = pathlib.Path(directory.name) / f"client-{index}.json"
                path.write_text(json.dumps(config))
                subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
                boxes.append(subprocess.Popen(["sing-box", "run", "-c", path], stderr=subprocess.PIPE))
                clients.append(associate(socks_port))

            def udp_request(index, name, payload, wait=True):
                _, sock, endpoint = clients[index]
                sock.sendto(b"\x00\x00\x00\x03" + bytes([len(name)]) + name +
                            struct.pack("!H", old_origin.getsockname()[1]) + payload, endpoint)
                if wait:
                    reply, _ = sock.recvfrom(65535)
                    if not reply.endswith(payload):
                        raise RuntimeError(f"wrong UDP reply: {reply!r}")

            # Warm the shared cache through SS UDP before any SOCKS lookup.
            udp_request(0, b"shared.example.test", b"before-udp-0")
            udp_request(1, b"shared.example.test", b"before-udp-1")
            if delivered != [[b"before-udp-0", b"before-udp-1"], []]:
                raise RuntimeError(f"wrong original UDP destination: {delivered!r}")
        for index in range(64):
            exchange(ports[index % 2], old_origin)
        for dns in (old_root, old_dns):
            with dns.lock:
                if [kind for name, kind in dns.queries] != [b"\x00\x01", b"\x00\x1c"]:
                    raise RuntimeError(f"inbound groups did not share same-name DNS views: {dns.queries!r}")
        pending = [greeting(port, b"pending.test", old_origin.getsockname()[1], False) for port in ports]
        if udp_mode:
            udp_request(0, b"pending.test", b"pending-udp-0", False)
            udp_request(1, b"pending.test", b"pending-udp-1", False)
        if coordinated:
            old_dns.wait_pending(1)
            deadline = time.monotonic() + 5
            expected_waiters = 4 if udp_mode else 2
            while True:
                process.stdin.write(b"counts\n")
                flights, waiters, direct = read_line(process)
                if (flights, waiters, direct) == (1, expected_waiters, 0):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"pending coordinated queries did not join: {(flights, waiters, direct)!r}")
                time.sleep(.01)
            with old_dns.lock:
                if len(old_dns.pending) != 1:
                    raise RuntimeError(f"coordinated inbounds sent duplicate queries: {len(old_dns.pending)}")
        else:
            old_dns.wait_pending(4 if udp_mode else 2)
        process.stdin.write(f"restart {new_root.port} {new_dns.port}\n".encode())
        seen, calls = read_line(process)
        new_ports = read_line(process)
        if seen != 4 or calls < 66:
            raise RuntimeError(f"old worker coverage: {seen}, {calls}")
        for client in pending:
            try:
                first = client.recv(1)
                if first:
                    response = first + exact(client, 9)
                    if not coordinated or response[0] != 5 or response[1] == 0 or response[2] != 0:
                        raise RuntimeError(f"old pending connection survived stop: {response!r}")
                    if client.recv(1):
                        raise RuntimeError("old failed connection did not close during stop")
            except ConnectionResetError:
                pass
        errors = []
        def fresh_request():
            try:
                exchange(new_ports[0], new_origin)
            except Exception as error:
                errors.append(error)
        first = threading.Thread(target=fresh_request)
        first.start()
        new_dns.wait_pending(1)
        old_dns.release()
        new_dns.release()
        first.join(timeout=8)
        if first.is_alive() or errors:
            raise RuntimeError(f"new generation request failed: {errors!r}")
        if udp_mode:
            # The new SOCKS lookup warmed both SS UDP groups in this generation.
            udp_request(0, b"shared.example.test", b"after-udp-0")
            udp_request(1, b"shared.example.test", b"after-udp-1")
            if delivered != [[b"before-udp-0", b"before-udp-1"], [b"after-udp-0", b"after-udp-1"]]:
                raise RuntimeError(f"wrong replacement UDP destination: {delivered!r}")
        for index in range(64):
            exchange(new_ports[index % 2], new_origin)
        for dns in (new_root, new_dns):
            with dns.lock:
                if [kind for name, kind in dns.queries] != [b"\x00\x01", b"\x00\x1c"]:
                    raise RuntimeError(f"new generation did not share fresh results: {dns.queries!r}")
        process.stdin.write(b"stop\n")
        seen, calls = read_line(process)
        if seen != 4 or calls < 65:
            raise RuntimeError(f"new worker coverage: {seen}, {calls}")
        if process.wait(timeout=5):
            raise RuntimeError(f"fixture failed: {process.stderr.read()!r}")
    finally:
        for client in pending:
            client.close()
        for tcp, udp, _ in clients:
            tcp.close()
            udp.close()
        for box in boxes:
            box.terminate()
            box.communicate(timeout=3)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        echo_stop.set()
        if echo_thread:
            echo_thread.join(timeout=3)
        for target in udp_targets:
            target.close()
        if directory:
            directory.cleanup()
        old_dns.close()
        new_dns.close()
        old_root.close()
        new_root.close()
        if echo_errors or (echo_thread and echo_thread.is_alive()):
            raise RuntimeError(f"UDP echo failure: {echo_errors!r}")
print("two SOCKS inbounds/four workers" + (" and two SS UDP groups" if udp_mode else "") +
      " share same-name DNS views, drain pending queries and isolate replacement generations")
