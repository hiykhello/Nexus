"""Exercise dual-family results and failure semantics against a local DNS peer."""
import socket
import subprocess
import sys
import threading
from pathlib import Path

client = Path(sys.argv[1]).resolve()


def scenario(mode):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(3)
    errors = []
    received = []

    def server():
        try:
            wanted = 1 if mode in ("cancel", "nxdomain", "limit") else 2
            for index in range(wanted):
                query, peer = sock.recvfrom(512)
                kind = int.from_bytes(query[-4:-2], "big")
                received.append(kind)
                if kind != (1 if index == 0 else 28):
                    raise RuntimeError(f"unexpected query type {kind}")
                if mode == "cancel" or (mode == "cancel-v6" and kind == 28):
                    return
                reply = bytearray(query)
                reply[2:4] = b"\x81\x80"
                if mode == "nxdomain" or (mode in ("conflict", "negative-conflict") and kind == 28):
                    reply[3] = 0x83
                elif mode == "servfail" and kind == 28:
                    reply[3] = 0x82
                elif mode == "nodata" or (mode == "v4" and kind == 28) or (mode in ("v6", "negative-conflict") and kind == 1):
                    reply[9] = 1
                    reply.extend(b"\xc0\x0e\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0e\xc0\x0e" + bytes(20))
                elif mode == "limit":
                    reply[7] = 65
                    reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01" * 65)
                elif mode == "canonical-conflict" and kind == 28:
                    reply[7] = 2
                    reply.extend(b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x04\x01b\xc0\x0e")
                    reply.extend(b"\x01b\xc0\x0e\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" + bytes.fromhex("20010db8000000000000000000000001"))
                else:
                    reply[7] = 1
                    payload = bytes.fromhex("c0000201") if kind == 1 else bytes.fromhex("20010db8000000000000000000000001")
                    reply.extend(b"\xc0\x0c" + kind.to_bytes(2, "big") + b"\x00\x01\x00\x00\x00\x3c" + len(payload).to_bytes(2, "big") + payload)
                sock.sendto(reply, peer)
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=server)
    thread.start()
    try:
        result = subprocess.run([client, str(sock.getsockname()[1]), mode], capture_output=True, timeout=5)
        thread.join(timeout=4)
        if result.returncode or thread.is_alive() or errors:
            raise RuntimeError(f"{mode}: client={result.returncode}, queries={received}, errors={errors}, stderr={result.stderr!r}")
    finally:
        sock.close()


for case in ("both", "cache", "v4", "v6", "nodata", "nxdomain", "conflict", "negative-conflict", "canonical-conflict", "limit", "servfail", "cancel", "cancel-v6"):
    scenario(case)
print("dual-family DNS results, failures and cancellation passed")
