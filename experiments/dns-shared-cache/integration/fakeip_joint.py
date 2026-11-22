"""FakeIP connections coalesce through the experimental DNS coordinator."""
import pathlib
import select
import socket
import struct
import subprocess
import sys
import time

fixture = pathlib.Path(sys.argv[1]).resolve()


def exact(sock, size):
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        result += chunk
    return result


def read_line(process):
    if not select.select([process.stdout], [], [], 5)[0]:
        raise RuntimeError("fixture response timeout")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError(f"fixture exited: {process.poll()}, {process.stderr.read()!r}")
    return line.split()


def wait_counts(process, expected):
    deadline = time.monotonic() + 5
    while True:
        process.stdin.write(b"counts\n")
        actual = tuple(map(int, read_line(process)))
        if actual == expected:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"coordinator counts {actual}, expected {expected}")
        time.sleep(.01)


def connect(port, address, destination):
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.settimeout(5)
    client.sendall(b"\x05\x01\x00")
    if exact(client, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting failed")
    client.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(address) + struct.pack("!H", destination))
    return client


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns, socket.socket() as origin:
    dns.bind(("127.0.0.1", 0)); dns.settimeout(5)
    origin.bind(("127.0.0.1", 0)); origin.listen(4); origin.settimeout(5)
    process = subprocess.Popen([fixture, str(dns.getsockname()[1])], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    clients = []
    try:
        port, shared, pending = read_line(process)
        port = int(port)
        clients = [connect(port, shared.decode(), origin.getsockname()[1]) for _ in range(2)]
        query, peer = dns.recvfrom(4096)
        if query[12:].lower() != b"\x06shared\x07example\x04test\x00\x00\x01\x00\x01":
            raise RuntimeError(f"unexpected shared DNS query: {query!r}")
        wait_counts(process, (1, 2, 0))
        if select.select([dns], [], [], .1)[0]:
            raise RuntimeError("FakeIP clients sent duplicate DNS queries")
        reply = bytearray(query); reply[2:4] = b"\x81\x80"; reply[7] = 1
        reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
        dns.sendto(reply, peer)
        for client in clients:
            if exact(client, 10)[:3] != b"\x05\x00\x00":
                raise RuntimeError("FakeIP SOCKS connection failed")
        upstreams = [origin.accept()[0] for _ in clients]
        try:
            payload = b"ping"
            for client in clients:
                client.sendall(payload)
            for upstream in upstreams:
                upstream.settimeout(5)
                if exact(upstream, len(payload)) != payload:
                    raise RuntimeError("upload failed")
                upstream.sendall(payload)
            for client in clients:
                if exact(client, len(payload)) != payload:
                    raise RuntimeError("download failed")
        finally:
            for upstream in upstreams:
                upstream.close()
        abandoned = connect(port, pending.decode(), origin.getsockname()[1])
        clients.append(abandoned)
        query, _ = dns.recvfrom(4096)
        if query[12:].lower() != b"\x07pending\x07example\x04test\x00\x00\x01\x00\x01":
            raise RuntimeError(f"unexpected pending DNS query: {query!r}")
        wait_counts(process, (1, 1, 0))
        process.stdin.write(b"stop\n")
        if process.wait(timeout=5):
            raise RuntimeError(f"fixture did not drain: {process.stderr.read()!r}")
        try:
            first = abandoned.recv(1)
            if first and (first + exact(abandoned, 9))[:2] == b"\x05\x00":
                raise RuntimeError("stopped FakeIP request succeeded")
        except ConnectionResetError:
            pass
    finally:
        for client in clients:
            client.close()
        if process.poll() is None:
            process.kill(); process.wait(timeout=5)
print("FakeIP sessions shared a DNS query and drained a pending query on stop")
