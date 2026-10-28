"""Exercise the experimental proxy FakeIP path with loopback peers only."""
import pathlib
import socket
import subprocess
import sys
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()


def exact(sock, count):
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise RuntimeError("unexpected EOF")
        result += part
    return result


def exercise(workers, block=False, stop_active=False):
    stop = threading.Event()
    failures = []
    queries = []
    http_requests = []
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.settimeout(0.1)
    target = socket.socket()
    target.bind(("127.0.0.1", 0))
    target.listen(8)
    target.settimeout(0.1)

    def dns_server():
        try:
            while not stop.is_set():
                try:
                    query, peer = upstream.recvfrom(512)
                except TimeoutError:
                    continue
                queries.append(query)
                if query[12:-4].lower() != b"\x07example\x04test\x00" or query[-4:] != b"\x00\x01\x00\x01":
                    raise RuntimeError("unexpected upstream query")
                reply = bytearray(query)
                reply[2:4] = b"\x81\x80"
                reply[7] = 2
                prefix = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04"
                reply.extend(prefix + b"\xc6\x12\x00\x01" + prefix + b"\x7f\x00\x00\x01")
                upstream.sendto(reply, peer)
        except Exception as error:
            failures.append(error)

    def target_server():
        try:
            while not stop.is_set():
                try:
                    conn, _ = target.accept()
                except TimeoutError:
                    continue
                with conn:
                    conn.settimeout(3)
                    first = exact(conn, 4)
                    if first == b"GET ":
                        request = first
                        while not request.endswith(b"\r\n\r\n") and len(request) < 4096:
                            request += exact(conn, 1)
                        http_requests.append(request)
                        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                        continue
                    if first != b"ping":
                        raise RuntimeError("incorrect payload")
                    conn.sendall(b"pong")
                    while conn.recv(32):
                        pass
        except Exception as error:
            failures.append(error)

    threads = [threading.Thread(target=dns_server), threading.Thread(target=target_server)]
    for thread in threads:
        thread.start()
    args = [str(binary), str(upstream.getsockname()[1]), str(workers)]
    if block:
        args.append("block")
    process = subprocess.Popen(args,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        port = int(process.stdout.readline())
        with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
            conn.settimeout(3)
            conn.sendall(b"\x05\x01\x00")
            if exact(conn, 2) != b"\x05\x00":
                raise RuntimeError("SOCKS greeting failed")
            conn.sendall(b"\x05\x01\x00\x01\xc6\x12\x00\x01" + target.getsockname()[1].to_bytes(2, "big"))
            reply = exact(conn, 10)
            if block:
                if reply[:2] != b"\x05\x02" or queries:
                    raise RuntimeError("domain preflight did not block before DNS")
                with socket.create_connection(("127.0.0.1", port), timeout=3) as http:
                    http.settimeout(3)
                    authority = f"198.18.0.1:{target.getsockname()[1]}"
                    http.sendall(f"GET http://{authority}/path HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
                    response = b""
                    while not response.endswith(b"\r\n\r\n") and len(response) < 4096:
                        response += exact(http, 1)
                    if not response.startswith(b"HTTP/1.1 403") or queries or http_requests:
                        raise RuntimeError("HTTP FakeIP domain preflight did not block before DNS")
                process.stdin.write("stop\n")
                process.stdin.flush()
                if process.wait(timeout=5) != 0:
                    raise RuntimeError("fixture failed")
                return
            if reply[:2] != b"\x05\x00":
                raise RuntimeError(f"SOCKS request failed: {reply!r}")
            conn.sendall(b"ping")
            if exact(conn, 4) != b"pong":
                raise RuntimeError("relay failed")
            process.stdin.write("blocked\n")
            process.stdin.flush()
            if int(process.stdout.readline().strip()) < 1:
                raise RuntimeError("FakeIP DNS candidate was not filtered")
            with socket.create_connection(("127.0.0.1", port), timeout=3) as unknown:
                unknown.settimeout(3)
                unknown.sendall(b"\x05\x01\x00")
                if exact(unknown, 2) != b"\x05\x00":
                    raise RuntimeError("second greeting failed")
                unknown.sendall(b"\x05\x01\x00\x01\xc6\x12\x00\x02" + target.getsockname()[1].to_bytes(2, "big"))
                if exact(unknown, 10)[:2] != b"\x05\x02":
                    raise RuntimeError("unknown FakeIP was not rejected")
            time.sleep(1.2)
            process.stdin.write("probe\n")
            process.stdin.flush()
            if process.stdout.readline().strip() != "full":
                raise RuntimeError("live connection did not pin FakeIP")
            if stop_active:
                process.stdin.write("stop\n")
                process.stdin.flush()
                if process.wait(timeout=5) != 0 or conn.recv(1):
                    raise RuntimeError("active connection did not close on stop")
                return
        with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
            conn.settimeout(3)
            authority = f"198.18.0.1:{target.getsockname()[1]}"
            conn.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            header = b""
            while not header.endswith(b"\r\n\r\n") and len(header) < 4096:
                header += exact(conn, 1)
            if not header.startswith(b"HTTP/1.1 200"):
                raise RuntimeError(f"HTTP CONNECT failed: {header!r}")
            conn.sendall(b"ping")
            if exact(conn, 4) != b"pong":
                raise RuntimeError("HTTP CONNECT relay failed")
        with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
            conn.settimeout(3)
            authority = f"198.18.0.1:{target.getsockname()[1]}"
            conn.sendall(f"GET http://{authority}/path?q=1 HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            header = b""
            while not header.endswith(b"\r\n\r\n") and len(header) < 4096:
                header += exact(conn, 1)
            if not header.startswith(b"HTTP/1.1 200") or exact(conn, 2) != b"ok":
                raise RuntimeError("ordinary HTTP forwarding failed")
            if not http_requests or not http_requests[-1].startswith(
                f"GET /path?q=1 HTTP/1.1\r\nHost: {authority}\r\n".encode()
            ):
                raise RuntimeError(f"unexpected forwarded request: {http_requests}")
        with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
            conn.settimeout(3)
            conn.sendall(b"\x05\x01\x00")
            if exact(conn, 2) != b"\x05\x00":
                raise RuntimeError("mapped greeting failed")
            mapped = bytes(10) + b"\xff\xff\xc6\x12\x00\x01"
            conn.sendall(b"\x05\x01\x00\x04" + mapped + target.getsockname()[1].to_bytes(2, "big"))
            if exact(conn, 10)[:2] != b"\x05\x00":
                raise RuntimeError("mapped FakeIP request failed")
            conn.sendall(b"ping")
            if exact(conn, 4) != b"pong":
                raise RuntimeError("mapped FakeIP relay failed")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            process.stdin.write("probe\n")
            process.stdin.flush()
            result = process.stdout.readline().strip()
            if result == "free":
                break
            if result != "full":
                raise RuntimeError(f"unexpected probe: {result}")
            time.sleep(0.05)
        else:
            raise RuntimeError("connection pin was not released")
        if not queries or failures:
            raise RuntimeError(f"upstream errors: {failures}")
        process.stdin.write("stop\n")
        process.stdin.flush()
        if process.wait(timeout=5) != 0:
            raise RuntimeError("fixture failed")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        stop.set()
        for thread in threads:
            thread.join(timeout=4)
        upstream.close()
        target.close()
    if failures or any(thread.is_alive() for thread in threads):
        raise RuntimeError(f"peer failure: {failures}")


def stop_pending_dns(workers):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream, socket.socket() as target:
        upstream.bind(("127.0.0.1", 0))
        upstream.settimeout(3)
        target.bind(("127.0.0.1", 0))
        target.listen(1)
        target.settimeout(0.5)
        process = subprocess.Popen([str(binary), str(upstream.getsockname()[1]), str(workers)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            port = int(process.stdout.readline())
            with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
                conn.settimeout(3)
                conn.sendall(b"\x05\x01\x00")
                if exact(conn, 2) != b"\x05\x00":
                    raise RuntimeError("pending DNS greeting failed")
                conn.sendall(b"\x05\x01\x00\x01\xc6\x12\x00\x01" + target.getsockname()[1].to_bytes(2, "big"))
                query, peer = upstream.recvfrom(512)
                if query[12:-4].lower() != b"\x07example\x04test\x00" or query[-4:] != b"\x00\x01\x00\x01":
                    raise RuntimeError("unexpected pending DNS query")
                time.sleep(1.2)
                process.stdin.write("probe\n")
                process.stdin.flush()
                if process.stdout.readline().strip() != "full":
                    raise RuntimeError("pending DNS did not retain the connection pin")
                process.stdin.write("halt\n")
                process.stdin.flush()
                if process.stdout.readline().strip() != "halted" or conn.recv(1):
                    raise RuntimeError("stop did not drain the pending session")
                reply = bytearray(query)
                reply[2:4] = b"\x81\x80"
                reply[7] = 1
                reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x7f\x00\x00\x01")
                upstream.sendto(reply, peer)
                process.stdin.write("probe\n")
                process.stdin.flush()
                if process.stdout.readline().strip() != "free":
                    raise RuntimeError("stop did not release the pending connection pin")
                try:
                    accepted, _ = target.accept()
                except TimeoutError:
                    pass
                else:
                    accepted.close()
                    raise RuntimeError("late DNS response triggered a connection")
            process.stdin.write("stop\n")
            process.stdin.flush()
            if process.wait(timeout=5) != 0:
                raise RuntimeError("pending DNS fixture failed")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


for count in (1, 2):
    exercise(count)
    stop_pending_dns(count)
exercise(2, block=True)
exercise(2, stop_active=True)
print("experimental proxy FakeIP routing, loop prevention and pin lifecycle passed")
