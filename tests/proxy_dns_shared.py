"""Prove distinct proxy workers reuse one configured DNS cache."""
import pathlib
import select
import socket
import struct
import subprocess
import sys
import threading

fixture = pathlib.Path(sys.argv[1]).resolve()


def exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        data += chunk
    return data


def run(workers):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns, socket.socket() as origin:
        dns.bind(("127.0.0.1", 0))
        dns.settimeout(0.1)
        origin.bind(("127.0.0.1", 0))
        origin.listen(16)
        origin.settimeout(5)
        stop = threading.Event()
        queries = []
        errors = []

        def serve_dns():
            try:
                while not stop.is_set():
                    try:
                        query, peer = dns.recvfrom(4096)
                    except TimeoutError:
                        continue
                    kind = query[-4:-2]
                    if query[12:-4].lower() != b"\x06shared\x07example\x04test\x00" or kind not in (b"\x00\x01", b"\x00\x1c") or query[-2:] != b"\x00\x01":
                        raise RuntimeError(f"unexpected DNS query {query!r}")
                    queries.append(query)
                    if kind == b"\x00\x01":
                        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
                        response = query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:] + answer
                    else:
                        # A cached NODATA response with an SOA in the authority section.
                        soa = b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c" + bytes(16) + b"\x00\x00\x00\x3c"
                        response = query[:2] + b"\x81\x80\x00\x01\x00\x00\x00\x01\x00\x00" + query[12:] + soa
                    dns.sendto(response, peer)
            except Exception as error:
                errors.append(error)

        server = threading.Thread(target=serve_dns)
        server.start()
        proc = subprocess.Popen([str(fixture), str(dns.getsockname()[1]), str(workers)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([proc.stdout], [], [], 5)[0]:
                raise RuntimeError("fixture failed to start")
            port = int(proc.stdout.readline())
            request_count = 96
            for index in range(request_count):
                with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                    client.settimeout(5)
                    client.sendall(b"\x05\x01\x00")
                    if exact(client, 2) != b"\x05\x00":
                        raise RuntimeError("SOCKS greeting failed")
                    name = b"Shared.Example.Test" if index % 2 else b"shared.example.test"
                    client.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", origin.getsockname()[1]))
                    if exact(client, 10)[:3] != b"\x05\x00\x00":
                        raise RuntimeError("SOCKS connection failed")
                    with origin.accept()[0] as peer:
                        client.sendall(b"ping")
                        if exact(peer, 4) != b"ping":
                            raise RuntimeError("upstream payload mismatch")
                        peer.sendall(b"pong")
                        if exact(client, 4) != b"pong":
                            raise RuntimeError("downstream payload mismatch")
            remaining, stderr = proc.communicate("stop\n", timeout=5)
            if proc.returncode:
                raise RuntimeError(f"fixture exited {proc.returncode}: {stderr}")
            seen_workers, cache_count, calls = map(int, remaining.strip().split())
            if (seen_workers, cache_count, calls) != (workers, 1, request_count):
                raise RuntimeError(f"worker/cache observations: {(seen_workers, cache_count, calls)}")
            if [query[-4:-2] for query in queries] != [b"\x00\x01", b"\x00\x1c"]:
                raise RuntimeError(f"unexpected DNS query types: {[query[-4:-2] for query in queries]}")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)
            stop.set()
            server.join(timeout=2)
        if errors:
            raise errors[0]


for count in (2, 4):
    run(count)
print("2 and 4 workers reuse one positive and one negative DNS response")
