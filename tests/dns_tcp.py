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


def scenario(mode):
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
                response = bytearray(request)
                response[2:4] = b"\x81\x80"
                response[7] = 1
                response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                if mode == "bad-id":
                    response[1] ^= 1
                if mode == "oversize":
                    conn.sendall((4097).to_bytes(2, "big"))
                    return
                frame = len(response).to_bytes(2, "big") + response
                if mode == "short":
                    conn.sendall(frame[:6])
                    return
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
        result = subprocess.run([CLIENT, str(port), mode], capture_output=True, timeout=6)
        if result.returncode:
            raise RuntimeError(f"{mode}: exit {result.returncode}: {result.stderr.decode(errors='replace')}")
    finally:
        worker.join(timeout=4)
    if worker.is_alive() or errors:
        raise RuntimeError(f"{mode}: server failed: {errors}")


for case in ("ok", "bad-id", "oversize", "short", "timeout", "cancel", "budget"):
    scenario(case)
print("DNS UDP-to-TCP fallback, framing and cancellation passed")
