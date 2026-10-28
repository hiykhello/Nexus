"""Check that cached DNS resolution sends only required upstream queries."""
import socket
import subprocess
import sys
import threading
from pathlib import Path

client = Path(sys.argv[1]).resolve()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
sock.settimeout(3)
errors = []


def server():
    try:
        for expected in (b"\x01a\x04test\x00", b"\x01a\x04test\x00", b"\x01a\x04test\x00",
                         b"\x07missing\x04test\x00", b"\x07missing\x04test\x00"):
            query, peer = sock.recvfrom(512)
            if not query[12:].startswith(expected):
                raise RuntimeError("unexpected query name or order")
            reply = bytearray(query)
            reply[2:4] = b"\x81\x83" if expected.startswith(b"\x07") else b"\x81\x80"
            if not expected.startswith(b"\x07"):
                reply[7] = 1
                reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x0a\x00\x04\xc0\x00\x02\x01")
            sock.sendto(reply, peer)
        sock.settimeout(0.2)
        try:
            sock.recvfrom(512)
            raise RuntimeError("extra upstream query")
        except TimeoutError:
            pass
    except Exception as exc:
        errors.append(exc)

worker = threading.Thread(target=server)
worker.start()
try:
    result = subprocess.run([client, str(sock.getsockname()[1])], capture_output=True, timeout=6)
    worker.join(timeout=4)
    if result.returncode or worker.is_alive() or errors:
        raise RuntimeError(f"client={result.returncode}, server={errors}, stderr={result.stderr!r}")
finally:
    sock.close()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
try:
    result = subprocess.run([client, str(sock.getsockname()[1]), "cancel"], capture_output=True, timeout=4)
    if result.returncode:
        raise RuntimeError(f"cancel client={result.returncode}, stderr={result.stderr!r}")
finally:
    sock.close()
for mode in ("nxdomain", "nodata", "servfail"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(4)
    errors = []
    process = subprocess.Popen([client, str(sock.getsockname()[1]), "race-" + mode],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def race_server():
        try:
            first, first_peer = sock.recvfrom(512)
            second, second_peer = sock.recvfrom(512)
            negative = bytearray(second)
            negative[2:4] = {"nxdomain": b"\x81\x83", "nodata": b"\x81\x80",
                             "servfail": b"\x81\x82"}[mode]
            if mode == "nodata":
                negative[9] = 1
                negative.extend(b"\xc0\x11\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x11\xc0\x11" + bytes(20))
            sock.sendto(negative, second_peer)
            if process.stdout.readline() != b"negative processed\n":
                raise RuntimeError("resolver did not report completing the newer query")
            positive = bytearray(first)
            positive[2:4] = b"\x81\x80"
            positive[7] = 1
            positive.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x0a\x00\x04\xc0\x00\x02\x01")
            sock.sendto(positive, first_peer)
            if mode != "servfail":
                third, peer = sock.recvfrom(512)
                positive[:2] = third[:2]
                sock.sendto(positive, peer)
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=race_server)
    worker.start()
    try:
        process.wait(timeout=8)
        worker.join(timeout=5)
        if process.returncode or worker.is_alive() or errors:
            raise RuntimeError(f"{mode}: client={process.returncode}, server={errors}, stderr={process.stderr.read()!r}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        sock.close()
for mode, count in (("nxdomain", 2), ("nodata", 2), ("disabled", 3), ("zero", 3)):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(4)
    errors = []

    def negative_server():
        try:
            for _ in range(count):
                query, peer = sock.recvfrom(512)
                reply = bytearray(query)
                reply[2:4] = b"\x81\x80" if mode == "nodata" else b"\x81\x83"
                reply[9] = 1
                minimum = 0 if mode == "zero" else 60
                reply.extend(b"\xc0\x15\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x15\xc0\x15" + bytes(16) + minimum.to_bytes(4, "big"))
                sock.sendto(reply, peer)
            sock.settimeout(0.2)
            try:
                sock.recvfrom(512)
                raise RuntimeError("unexpected upstream query")
            except TimeoutError:
                pass
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=negative_server)
    worker.start()
    try:
        result = subprocess.run([client, str(sock.getsockname()[1]), "negative-" + mode], capture_output=True, timeout=6)
        worker.join(timeout=5)
        if result.returncode or worker.is_alive() or errors:
            raise RuntimeError(f"{mode}: client={result.returncode}, server={errors}, stderr={result.stderr!r}")
    finally:
        sock.close()
for mode, count in (("alias-nxdomain", 2), ("alias-nodata", 2), ("alias-zero", 3),
                    ("inline-nxdomain", 2), ("inline-zero", 3),
                    ("inline-nodata", 2), ("inline-nodata-zero", 3)):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(4)
    errors = []

    def alias_server():
        try:
            for _ in range(count):
                query, peer = sock.recvfrom(512)
                if not query[12:].startswith(b"\x08negative\x04test\x00"):
                    raise RuntimeError("expected original query")
                reply = bytearray(query)
                reply[2:4] = b"\x81\x83" if mode.startswith("inline-") and "nodata" not in mode else b"\x81\x80"
                reply[7] = 1
                ttl = 0 if mode.endswith("zero") else 5
                alias = b"\x07missing\x04test\x00"
                reply.extend(b"\xc0\x0c\x00\x05\x00\x01" + ttl.to_bytes(4, "big") + len(alias).to_bytes(2, "big") + alias)
                if mode.startswith("inline-"):
                    reply[9] = 1
                    reply.extend(b"\xc0\x15\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x15\xc0\x15" + bytes(16) + (60).to_bytes(4, "big"))
                    sock.sendto(reply, peer)
                    continue
                sock.sendto(reply, peer)
                query, peer = sock.recvfrom(512)
                if not query[12:].startswith(alias):
                    raise RuntimeError("expected CNAME target query")
                reply = bytearray(query)
                reply[2:4] = b"\x81\x80" if mode == "alias-nodata" else b"\x81\x83"
                reply[9] = 1
                reply.extend(b"\xc0\x14\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x14\xc0\x14" + bytes(16) + (60).to_bytes(4, "big"))
                sock.sendto(reply, peer)
            sock.settimeout(0.2)
            try:
                sock.recvfrom(512)
                raise RuntimeError("unexpected upstream query")
            except TimeoutError:
                pass
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=alias_server)
    worker.start()
    try:
        result = subprocess.run([client, str(sock.getsockname()[1]), "negative-" + mode], capture_output=True, timeout=6)
        worker.join(timeout=5)
        if result.returncode or worker.is_alive() or errors:
            raise RuntimeError(f"{mode}: client={result.returncode}, server={errors}, stderr={result.stderr!r}")
    finally:
        sock.close()
for mode in ("direct", "inline"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(4)
    errors = []

    def invalid_negative_server():
        try:
            for _ in range(3):
                query, peer = sock.recvfrom(512)
                reply = bytearray(query)
                reply[2:4] = b"\x81\x80"
                reply[7] = 2 if mode == "inline" else 1
                reply[9] = 1
                if mode == "inline":
                    alias = b"\x07missing\x04test\x00"
                    reply.extend(b"\xc0\x0c\x00\x05\x00\x01" + (60).to_bytes(4, "big") + len(alias).to_bytes(2, "big") + alias)
                # An unrelated address must not be turned into cached NODATA.
                reply.extend(b"\x05other\x04test\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01")
                reply.extend(b"\xc0\x15\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x15\xc0\x15" + bytes(16) + (60).to_bytes(4, "big"))
                sock.sendto(reply, peer)
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=invalid_negative_server)
    worker.start()
    try:
        result = subprocess.run([client, str(sock.getsockname()[1]), "negative-invalid-" + mode], capture_output=True, timeout=6)
        worker.join(timeout=5)
        if result.returncode or worker.is_alive() or errors:
            raise RuntimeError(f"invalid {mode}: client={result.returncode}, server={errors}, stderr={result.stderr!r}")
    finally:
        sock.close()
print("DNS cache hit, negative TTL, isolation, races and cancellation passed")
