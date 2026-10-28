"""Controlled multi-response DNS alias resolution."""
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

CLIENT = Path(sys.argv[1]).resolve()


def scenario(mode):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(3)
    port = sock.getsockname()[1]
    errors = []
    def server():
        try:
            first, source = sock.recvfrom(512)
            if (mode != "system" and first[:2] != b"\x10\x01") or first[12:20] != b"\x01a\x04test\x00":
                raise RuntimeError("unexpected first query")
            if mode == "cancel":
                time.sleep(0.3)
                return
            reply = bytearray(first)
            reply[2:4] = b"\x81\x80"
            if mode in ("nxdomain", "servfail", "refused", "empty", "nodata", "referral", "wrong-zone", "edns"):
                reply[3] |= {"nxdomain": 3, "servfail": 2, "refused": 5}.get(mode, 0)
                if mode in ("nodata", "wrong-zone"):
                    reply[9] = 1
                    owner = b"\xc0\x0e" if mode == "nodata" else b"\x05other\x00"
                    reply.extend(owner + b"\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0e\xc0\x0e" + bytes(20))
                if mode == "referral":
                    reply[9] = 1
                    reply.extend(b"\xc0\x0e\x00\x02\x00\x01\x00\x00\x00\x3c\x00\x02\xc0\x0e")
                if mode == "edns":
                    reply[11] = 1
                    reply.extend(b"\x00\x00\x29\x10\x00\x01\x00\x00\x00\x00\x00")
                sock.sendto(reply, source)
                return
            reply[7] = 1
            reply.extend(b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x14\x00\x04\x01b\xc0\x0e")
            if mode == "cross-family-conflict":
                reply[7] = 2
                reply.extend(b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" + bytes.fromhex("20010db8000000000000000000000001"))
                sock.sendto(reply, source)
                return
            sock.sendto(reply, source)
            second, peer = sock.recvfrom(512)
            if (mode != "system" and second[:2] != b"\x10\x02") or second[12:20] != b"\x01b\x04test\x00":
                raise RuntimeError("unexpected second query")
            reply = bytearray(second)
            reply[2:4] = b"\x81\x80"
            reply[7] = 1
            if mode == "loop":
                reply.extend(b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x0a\x00\x04\x01a\xc0\x0e")
            else:
                reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01")
            sock.sendto(reply, peer)
        except Exception as exc:
            errors.append(exc)
        finally:
            sock.close()
    worker = threading.Thread(target=server)
    worker.start()
    try:
        result = subprocess.run([CLIENT, str(port), mode], capture_output=True, timeout=5)
        if result.returncode:
            raise RuntimeError(f"{mode}: exit {result.returncode}: {result.stderr.decode(errors='replace')}")
    finally:
        worker.join(timeout=4)
    if worker.is_alive() or errors:
        raise RuntimeError(f"{mode}: server failed: {errors}")


for case in ("ok", "system", "loop", "cancel", "nxdomain", "nodata", "referral", "wrong-zone", "empty", "servfail", "refused", "edns", "cross-family-conflict"):
    scenario(case)
result = subprocess.run([CLIENT, "53", "random"], capture_output=True, timeout=5)
if result.returncode:
    raise RuntimeError(f"random failure: exit {result.returncode}")
print("DNS multi-response alias, TTL, cancellation and random failure passed")
