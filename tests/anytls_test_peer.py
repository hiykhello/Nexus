"""Independent framed TLS peer for production AnyTLS lifecycle tests."""
import hashlib
import socket
import ssl
import struct

from dns_rule_support import exact


def address(host, port, uot=False):
    try:
        family, raw = socket.AF_INET, socket.inet_pton(socket.AF_INET, host)
    except OSError:
        try:
            family, raw = socket.AF_INET6, socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            raw = host.encode()
            if not 0 < len(raw) <= 255:
                raise ValueError("invalid test domain")
            return bytes([2 if uot else 3, len(raw)]) + raw + struct.pack("!H", port)
    tag = (0 if family == socket.AF_INET else 1) if uot else (1 if family == socket.AF_INET else 4)
    return bytes([tag]) + raw + struct.pack("!H", port)


def datagram(host, port, payload):
    return address(host, port, True) + struct.pack("!H", len(payload)) + payload


class Peer:
    def __init__(self, root, port, password="anytls-network-secret", host="127.0.0.1", version=2):
        self.raw = socket.create_connection((host, port), timeout=5)
        context = ssl.create_default_context(cafile=str(root / "cert"))
        self.socket = context.wrap_socket(self.raw, server_hostname="localhost")
        self.socket.settimeout(5)
        self.pending, self.acks, self.ended, self.ids = {}, {}, set(), 0
        authentication = hashlib.sha256(password.encode()).digest() + b"\x00\x0b" + bytes(11)
        for begin in range(0, len(authentication), 3):
            self.socket.sendall(authentication[begin:begin + 3])
        self.frame(4, 0, f"v={version}\nclient=\npadding-md5={'0' * 32}".encode(), fragmented=True)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.socket.close()

    def frame(self, command, stream, payload=b"", fragmented=False):
        wire = struct.pack("!BIH", command, stream, len(payload)) + payload
        if fragmented:
            for begin, end in ((0, 1), (1, 5), (5, 9), (9, len(wire))):
                self.socket.sendall(wire[begin:end])
        else:
            self.socket.sendall(wire)

    def next(self):
        command, stream, length = struct.unpack("!BIH", exact(self.socket, 7))
        payload = exact(self.socket, length)
        if command == 2:
            self.pending.setdefault(stream, bytearray()).extend(payload)
        elif command == 3:
            self.ended.add(stream)
        elif command == 7:
            self.acks[stream] = payload
        elif command == 8:
            self.frame(9, stream)
        elif command == 5:
            raise RuntimeError(f"AnyTLS alert: {payload!r}")
        return command, stream, payload

    def open(self, host, port, payload=b"", fragmented=False):
        self.ids += 1
        stream = self.ids
        self.frame(1, stream, fragmented=fragmented)
        self.send(stream, address(host, port) + payload, fragmented)
        return stream

    def send(self, stream, payload, fragmented=False):
        for begin in range(0, len(payload), 60000):
            self.frame(2, stream, payload[begin:begin + 60000], fragmented)

    def ack(self, stream, accepted=True):
        while stream not in self.acks:
            if stream in self.ended:
                raise RuntimeError("AnyTLS FIN arrived before SYNACK")
            self.next()
        if bool(self.acks[stream]) == accepted:
            raise RuntimeError(f"AnyTLS SYNACK accepted={not bool(self.acks[stream])}, expected={accepted}")

    def read(self, stream, count):
        while len(self.pending.get(stream, b"")) < count:
            if stream in self.ended:
                raise RuntimeError(f"AnyTLS stream {stream} ended before {count} bytes")
            self.next()
        result = bytes(self.pending[stream][:count])
        del self.pending[stream][:count]
        return result

    def finish(self, stream):
        self.frame(3, stream)

    def read_datagram(self, stream):
        tag = self.read(stream, 1)[0]
        if tag not in (0, 1, 2):
            raise RuntimeError(f"invalid UoT reply family: {tag}")
        size = self.read(stream, 1)[0] if tag == 2 else 4 if tag == 0 else 16
        host = self.read(stream, size)
        port = int.from_bytes(self.read(stream, 2), "big")
        length = int.from_bytes(self.read(stream, 2), "big")
        return tag, host, port, self.read(stream, length)
