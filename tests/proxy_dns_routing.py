"""Exercise ordered DNS server selection through the proxy on loopback."""
import os
import collections
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()
guard = pathlib.Path(sys.argv[2]).resolve()
workers = int(sys.argv[3]) if len(sys.argv) > 3 else 1
stop = threading.Event()
errors = []
queries = [[], []]
sockets = []
threads = []


def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data


def serve_dns(sock, index):
    try:
        while not stop.is_set():
            try:
                query, peer = sock.recvfrom(512)
            except TimeoutError:
                continue
            kind = int.from_bytes(query[-4:-2], "big")
            queries[index].append((query[12:-4].lower(), kind))
            reply = bytearray(query)
            reply[2:4] = b"\x81\x80"
            if query[12:-4].lower() == b"\x04fail\x07example\x00":
                reply[3] = 0x82
            elif kind == 1:
                reply[7] = 1
                reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00" + bytes([index + 1]))
            elif kind == 28:
                reply[9] = 1
                reply.extend(b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c" + bytes(20))
            else:
                raise RuntimeError(f"unexpected query type {kind}")
            sock.sendto(reply, peer)
    except Exception as exc:
        errors.append(exc)


def serve_target(sock, index):
    try:
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except TimeoutError:
                continue
            with conn:
                conn.sendall(bytes([index + 1]))
    except Exception as exc:
        errors.append(exc)


def listen(kind, address):
    sock = socket.socket(socket.AF_INET, kind)
    sock.bind(address)
    if kind == socket.SOCK_STREAM:
        sock.listen(16)
    sock.settimeout(0.1)
    sockets.append(sock)
    return sock


def start(target, *args):
    thread = threading.Thread(target=target, args=args)
    thread.start()
    threads.append(thread)


try:
    dns = [listen(socket.SOCK_DGRAM, ("127.0.0.1", 0)) for _ in range(2)]
    target1 = listen(socket.SOCK_STREAM, ("127.0.0.1", 0))
    target_port = target1.getsockname()[1]
    target2 = listen(socket.SOCK_STREAM, ("127.0.0.2", target_port))
    for index in range(2):
        start(serve_dns, dns[index], index)
        start(serve_target, (target1, target2)[index], index)
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    extra_probe = socket.socket()
    extra_probe.bind(("127.0.0.1", 0))
    extra_port = extra_probe.getsockname()[1]
    extra_probe.close()
    if extra_port == port:
        raise RuntimeError("listener port collision")
    with tempfile.TemporaryDirectory() as tmp:
        config = pathlib.Path(tmp) / "proxy.kdl"
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
dns {{
  servers {{
    udp "first" host="127.0.0.1" port={dns[0].getsockname()[1]}
    udp "second" host="127.0.0.1" port={dns[1].getsockname()[1]}
  }}
  rules {{
    - domain="exact.example" server="first"
    - domain-suffix="example" server="second"
  }}
  final "first"
}}
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}; socks5 "other" {{ listen host="127.0.0.1" port={extra_port}; authentication "none"; }}; }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
        env = os.environ.copy()
        env["LD_PRELOAD"] = str(guard)
        proc = subprocess.Popen([binary, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
        try:
            deadline = time.monotonic() + 5
            while True:
                if proc.poll() is not None:
                    raise RuntimeError(f"proxy exited: {proc.stderr.read()!r}")
                try:
                    sock = socket.create_connection(("127.0.0.1", port), timeout=1)
                    sock.close()
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)
            for name, expected in [("EXACT.Example", 1), ("Sub.Example", 2), ("example", 2), ("notexample", 1), ("Sub.Example", 2)]:
                with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                    sock.settimeout(3)
                    sock.sendall(b"\x05\x01\x00")
                    assert exact(sock, 2) == b"\x05\x00"
                    encoded = name.encode("ascii")
                    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded + target_port.to_bytes(2, "big"))
                    assert exact(sock, 10)[:4] == b"\x05\x00\x00\x01"
                    assert exact(sock, 1) == bytes([expected])
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.settimeout(3)
                sock.sendall(b"\x05\x01\x00")
                assert exact(sock, 2) == b"\x05\x00"
                name = b"fail.example"
                sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + target_port.to_bytes(2, "big"))
                assert exact(sock, 10)[:4] == b"\x05\x04\x00\x01"
            with socket.create_connection(("127.0.0.1", extra_port), timeout=2) as sock:
                sock.settimeout(3)
                sock.sendall(b"\x05\x01\x00")
                assert exact(sock, 2) == b"\x05\x00"
                name = b"Sub.Example"
                sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + target_port.to_bytes(2, "big"))
                assert exact(sock, 10)[:4] == b"\x05\x00\x00\x01"
                assert exact(sock, 1) == b"\x02"
            expected = [
                {(b"\x05exact\x07example\x00", 1): 1, (b"\x05exact\x07example\x00", 28): 1,
                 (b"\x0anotexample\x00", 1): 1, (b"\x0anotexample\x00", 28): 1},
                {(b"\x03sub\x07example\x00", 1): 1, (b"\x03sub\x07example\x00", 28): 3,
                 (b"\x07example\x00", 1): 1, (b"\x07example\x00", 28): 1,
                 (b"\x04fail\x07example\x00", 1): 1},
            ]
            # Both listeners share positive answers. The peer's zero SOA
            # MINIMUM deliberately prevents reuse of the three AAAA misses.
            if [collections.Counter(items) for items in queries] != expected:
                raise RuntimeError(f"unexpected DNS queries: {queries}")
            if errors:
                raise RuntimeError(f"server errors: {errors}")
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            stderr = proc.stderr.read()
            if proc.returncode or b"unexpected-system-resolver" in stderr:
                raise RuntimeError(f"proxy exit {proc.returncode}: {stderr!r}")
finally:
    stop.set()
    for thread in threads:
        thread.join(timeout=2)
    for sock in sockets:
        sock.close()
print("DNS routing, cross-inbound shared positives and uncached zero-TTL negatives passed")
