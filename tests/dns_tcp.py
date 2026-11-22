"""Controlled UDP truncation and DNS-over-TCP framing interoperability."""
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

CLIENT = Path(sys.argv[1]).resolve()


def exact(conn, count):
    data = bytearray()
    while len(data) < count:
        part = conn.recv(count-len(data))
        if not part:
            raise RuntimeError("unexpected TCP EOF")
        data.extend(part)
    return bytes(data)


def scenario(mode, backend, advertised=1232):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp.bind(("127.0.0.1", 0))
    port = udp.getsockname()[1]
    tcp.bind(("127.0.0.1", port))
    tcp.listen(1)
    udp.settimeout(3)
    tcp.settimeout(3)
    errors = []
    def server():
        try:
            request, source = udp.recvfrom(512)
            truncated = bytearray(request)
            truncated[2:4] = b"\x83\x80"
            if mode == "capacity":
                accepted = max(advertised, 512)
                if accepted < 65507:
                    oversized = truncated + bytes(accepted + 1 - len(truncated))
                    udp.sendto(oversized, source)
                    tcp.settimeout(0.1)
                    try:
                        unexpected, _ = tcp.accept()
                    except socket.timeout:
                        pass
                    else:
                        unexpected.close()
                        raise RuntimeError("oversized UDP TC prefix triggered TCP fallback")
                    finally:
                        tcp.settimeout(3)
                # Ordinary IPv4 UDP tops out at 65507 bytes, even when the
                # EDNS advertisement permits 65535-byte DNS messages.
                truncated.extend(bytes(min(accepted, 65507) - len(truncated)))
            if mode == "budget":
                time.sleep(0.15)
            udp.sendto(truncated, source)
            conn, _ = tcp.accept()
            with conn:
                conn.settimeout(2)
                size = int.from_bytes(exact(conn, 2), "big")
                tcp_request = exact(conn, size)
                if tcp_request != request:
                    raise RuntimeError("TCP query differs from UDP query")
                if mode in ("timeout", "cancel", "budget"):
                    time.sleep(0.4)
                    return
                response = bytearray(request[:29])
                response[2:4] = b"\x81\x80"
                response[7] = 1
                response[11] = 0
                response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                if mode == "bad-id":
                    response[1] ^= 1
                if mode == "large":
                    response[7] = 2
                    text = bytearray()
                    while len(text) < 5000:
                        length = min(255, 4999 - len(text))
                        text.extend(bytes([length]) + b"x" * length)
                    response.extend(b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c" + len(text).to_bytes(2, "big") + text)
                if mode == "capacity":
                    response[7] = 2
                    length = (65535 if advertised == 65535 else 5000) - len(response) - 12
                    response.extend(b"\xc0\x0c\xfd\xe8\x00\x01\x00\x00\x00\x3c" + length.to_bytes(2, "big") + b"x" * length)
                frame = len(response).to_bytes(2, "big") + response
                if mode == "short":
                    conn.sendall(frame[:6])
                    return
                if mode == "capacity":
                    conn.sendall(frame)
                else:
                    for byte in frame:
                        conn.sendall(bytes([byte]))
        except Exception as exc:
            errors.append(exc)
        finally:
            udp.close()
            tcp.close()
    worker = threading.Thread(target=server)
    worker.start()
    try:
        result = subprocess.run([CLIENT, str(port), mode, backend, str(advertised)], capture_output=True, timeout=6)
        if result.returncode:
            raise RuntimeError(f"{backend} {mode}: exit {result.returncode}: {result.stderr.decode(errors='replace')}")
    finally:
        worker.join(timeout=4)
    if worker.is_alive() or errors:
        raise RuntimeError(f"{mode}: server failed: {errors}")


backends = ["epoll"]
if subprocess.check_output([CLIENT, "has-uring"], text=True).strip() == "yes":
    backends.append("uring")
for backend in backends:
    for case in ("ok", "large", "bad-id", "short", "timeout", "cancel", "budget"):
        scenario(case, backend)
    for advertised in (0, 512, 4096, 65535):
        scenario("capacity", backend, advertised)
    print(f"DNS UDP-to-TCP fallback, oversized TC rejection, capacity boundaries, framing and cancellation passed ({backend})")
