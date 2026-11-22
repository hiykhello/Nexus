"""Local DNS and echo peers for question-policy network tests."""
import base64
import contextlib
import errno
import json
import select
import socket
import struct
import subprocess
import threading
import time


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        result.extend(chunk)
    return bytes(result)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def connect(port):
    deadline = time.monotonic() + 5
    while True:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=3)
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.01)


def question(packet):
    pos, labels = 12, []
    while packet[pos]:
        size = packet[pos]
        labels.append(packet[pos + 1:pos + size + 1].decode("ascii"))
        pos += size + 1
    pos += 1
    return ".".join(labels).lower(), int.from_bytes(packet[pos:pos + 2], "big"), pos + 4


def wire_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def dns_request(port, name, transport=socket.SOCK_DGRAM, identifier=0x1234, kind=1):
    query = struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0) + wire_name(name) + struct.pack("!HH", kind, 1)
    if transport == socket.SOCK_STREAM:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.sendall(struct.pack("!H", len(query)) + query)
            wire = exact(client, int.from_bytes(exact(client, 2), "big"))
    else:
        with socket.socket(socket.AF_INET, transport) as client:
            client.settimeout(3)
            client.sendto(query, ("127.0.0.1", port))
            wire = client.recv(1024)
    reply_id, flags, questions, answers = struct.unpack_from("!4H", wire)
    assert (reply_id, questions) == (identifier, 1)
    family, width = (socket.AF_INET, 4) if kind == 1 else (socket.AF_INET6, 16)
    return flags & 15, socket.inet_ntop(family, wire[-width:]) if answers else None


def bind_same_port(endpoints, port=0, ipv6_only=False):
    for attempt in range(16):
        selected = port
        with contextlib.ExitStack() as pending:
            sockets = []
            try:
                for family, kind, host in endpoints:
                    sock = pending.enter_context(socket.socket(family, kind))
                    if ipv6_only and family == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock.bind((host, selected))
                    selected = sock.getsockname()[1]
                    sockets.append(sock)
            except OSError as error:
                if port or error.errno != errno.EADDRINUSE or attempt == 15:
                    raise
            else:
                pending.pop_all()
                return selected, sockets


class DnsPeer:
    def __init__(self, ipv6=False, host=None, port=0):
        self.ipv6, self.stop, self.seen, self.errors = ipv6, threading.Event(), [], []
        self.family = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.host = host or ("::1" if ipv6 else "127.0.0.1")
        self.aliases, self.no_data, self.drop, self.gates, self.delays = {}, set(), set(), {}, {}
        self.port, (self.udp, self.tcp) = bind_same_port((
            (self.family, socket.SOCK_DGRAM, self.host), (self.family, socket.SOCK_STREAM, self.host),
        ), port)
        self.tcp.listen(32)
        self.udp.settimeout(.1)
        self.tcp.settimeout(.1)
        self.threads = [threading.Thread(target=self.serve_udp), threading.Thread(target=self.serve_tcp)]

    def reply(self, packet, transport):
        name, kind, end = question(packet)
        self.seen.append((name, kind, transport))
        if delay := self.delays.get((name, kind)):
            time.sleep(delay)
        if gate := self.gates.get((name, kind)):
            if not gate.wait(4):
                raise RuntimeError("DNS test gate timed out")
        mode = name.split(".")[0]
        if (name, kind) in self.drop or (mode == "pending" and kind == 28):
            return None
        if mode == "coalesce":
            time.sleep(.1)
        nx = mode == "nx" or (mode == "conflict" and kind == 28)
        nodata = (name, kind) in self.no_data or (name == "upstream.test" and kind == 28) or (mode == "no-a" and kind == 1) or \
            (mode == "no-b" and kind == 28) or (mode == "conflict" and kind == 1)
        code = 3 if nx else 5 if mode == "refused" else 2 if mode == "servfail" and kind == 28 else 0
        records, authority = b"", b""
        if nodata or nx:
            authority = b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c" + bytes(16) + struct.pack("!I", 60)
        elif code == 0:
            terminal = ("a.test" if kind == 1 else "b.test") if mode == "mismatch" else \
                "canonical.test" if mode == "alias" else self.aliases.get(name, name)
            owner = b"\xc0\x0c"
            if terminal != name:
                cname = wire_name(terminal)
                records += owner + b"\x00\x05\x00\x01\x00\x00\x00\x3c" + struct.pack("!H", len(cname)) + cname
                owner = cname
            count = (40 if kind == 1 else 25) if mode == "many" else (33 if kind == 1 else 31) if mode == "limit" else 1
            address = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6, "127.0.0.1" if kind == 1 else "::1")
            record = owner + struct.pack("!HHIH", kind, 1, 60, len(address)) + address
            records += record * count
        count = 0 if nodata or code else (1 + (terminal != name) if mode not in ("many", "limit") else count)
        return packet[:2] + struct.pack("!HHHHH", 0x8180 | code, 1, count, int(bool(authority)), 0) + packet[12:end] + records + authority

    def serve_udp(self):
        try:
            while not self.stop.is_set():
                try:
                    packet, peer = self.udp.recvfrom(4096)
                except TimeoutError:
                    continue
                response = self.reply(packet, "udp")
                if response is not None:
                    self.udp.sendto(response, peer)
        except Exception as error:
            self.errors.append(error)

    def serve_tcp(self):
        try:
            while not self.stop.is_set():
                try:
                    peer, _ = self.tcp.accept()
                except TimeoutError:
                    continue
                with peer:
                    peer.settimeout(3)
                    packet = exact(peer, int.from_bytes(exact(peer, 2), "big"))
                    response = self.reply(packet, "tcp")
                    if response is None:
                        self.stop.wait(5)
                    else:
                        peer.sendall(struct.pack("!H", len(response)) + response)
        except Exception as error:
            self.errors.append(error)

    def count(self, name, kind):
        return sum(item[:2] == (name, kind) for item in self.seen)

    def __enter__(self):
        for thread in self.threads:
            thread.start()
        return self

    def __exit__(self, kind, *_):
        self.stop.set()
        for thread in self.threads:
            thread.join(6)
        self.udp.close()
        self.tcp.close()
        if kind is None and self.errors:
            raise self.errors[0]


class Echo:
    def __init__(self):
        self.stop, self.errors, self.threads = threading.Event(), [], []
        self.accepted, self.received = [], []
        self.port, self.sockets = bind_same_port([
            (family, kind, host)
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1"))
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM)
        ], ipv6_only=True)
        for sock in self.sockets:
            sock.settimeout(.1)
            if sock.type == socket.SOCK_STREAM:
                sock.listen(64)
            self.threads.append(threading.Thread(target=self.serve, args=(sock, sock.type)))

    def serve(self, sock, kind):
        try:
            while not self.stop.is_set():
                try:
                    if kind == socket.SOCK_DGRAM:
                        data, peer = sock.recvfrom(65535)
                        self.received.append(data)
                        sock.sendto(data, peer)
                    else:
                        peer, _ = sock.accept()
                        self.accepted.append(sock.family)
                        with peer:
                            peer.settimeout(3)
                            data = peer.recv(4096)
                            if data:
                                peer.sendall(data)
                except TimeoutError:
                    continue
        except Exception as error:
            self.errors.append(error)

    def __enter__(self):
        for thread in self.threads:
            thread.start()
        return self

    def __exit__(self, kind, *_):
        self.stop.set()
        for thread in self.threads:
            thread.join(4)
        for sock in self.sockets:
            sock.close()
        if kind is None and self.errors:
            raise self.errors[0]


@contextlib.contextmanager
def nexus_process(binary, config, listeners=1):
    process = subprocess.Popen(["stdbuf", "-oL", binary, "run", "--config", config],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    try:
        for _ in range(listeners):
            if not select.select([process.stdout], [], [], 5)[0] or b"listening" not in process.stdout.readline():
                raise RuntimeError("Nexus listener did not start")
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        _, diagnostics = process.communicate(timeout=5)
        if process.returncode:
            raise RuntimeError(f"Nexus exit {process.returncode}: {diagnostics!r}")


def stream_request(front, origin, name, success=True, http=False, code=None):
    with connect(front) as client:
        if http:
            client.sendall(f"CONNECT {name}:{origin} HTTP/1.1\r\nHost: {name}:{origin}\r\n\r\n".encode())
            response = bytearray()
            while not response.endswith(b"\r\n\r\n"):
                response.extend(exact(client, 1))
            accepted = response.startswith(b"HTTP/1.1 200")
            if code is not None and not response.startswith(f"HTTP/1.1 {code} ".encode()):
                raise RuntimeError(f"{name}: unexpected HTTP response {response!r}")
        else:
            client.sendall(b"\x05\x01\x00")
            if exact(client, 2) != b"\x05\x00":
                raise RuntimeError("SOCKS greeting failed")
            raw = name.encode()
            client.sendall(b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + struct.pack("!H", origin))
            header = exact(client, 4)
            accepted = header[1] == 0
            if code is not None and header[1] != code:
                raise RuntimeError(f"{name}: unexpected SOCKS response {header!r}")
            if header[3] not in (1, 4):
                raise RuntimeError(f"invalid SOCKS reply: {header!r}")
            exact(client, 6 if header[3] == 1 else 18)
        if accepted != success:
            raise RuntimeError(f"{name}: accepted={accepted}, expected={success}")
        if accepted:
            client.sendall(b"question-policy")
            response = exact(client, 15)
            if response != b"question-policy":
                raise RuntimeError(f"{name}: stream response mismatch {response!r}")


@contextlib.contextmanager
def udp_client(front):
    with connect(front) as control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(("127.0.0.1", 0))
        client.settimeout(3)
        control.sendall(b"\x05\x01\x00")
        if exact(control, 2) != b"\x05\x00":
            raise RuntimeError("UDP greeting failed")
        control.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", client.getsockname()[1]))
        response = exact(control, 10)
        if response[:4] != b"\x05\x00\x00\x01":
            raise RuntimeError("UDP association failed")
        yield client, (socket.inet_ntoa(response[4:8]), int.from_bytes(response[8:10], "big"))


def datagram_request(client, relay, origin, name, success=True):
    raw = name.encode()
    packet = b"\x00\x00\x00\x03" + bytes([len(raw)]) + raw + struct.pack("!H", origin) + b"question-datagram"
    client.sendto(packet, relay)
    client.settimeout(3 if success else .25)
    try:
        response, _ = client.recvfrom(65535)
        if not success or not response.endswith(b"question-datagram"):
            raise RuntimeError(f"{name}: unexpected UDP response")
    except TimeoutError:
        if success:
            raise


@contextlib.contextmanager
def proxy_client(root, outbound):
    client_port = free_port()
    path = root / "sing-box.json"
    path.write_text(json.dumps({
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": client_port}],
        "outbounds": [dict(outbound, tag="edge")],
        "route": {"final": "edge"},
    }))
    box = subprocess.Popen(["sing-box", "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        yield client_port
    finally:
        box.terminate()
        _, diagnostics = box.communicate(timeout=5)
        if box.returncode:
            raise RuntimeError(f"sing-box exit {box.returncode}: {diagnostics!r}")


@contextlib.contextmanager
def ss_client(root, port, key):
    outbound = {"type": "shadowsocks", "server": "127.0.0.1", "server_port": port,
                "method": "2022-blake3-aes-128-gcm", "password": base64.b64encode(key).decode()}
    with proxy_client(root, outbound) as client_port, udp_client(client_port) as client:
        yield client


