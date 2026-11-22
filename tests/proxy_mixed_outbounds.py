#!/usr/bin/env python3
"""Exercise both outbound types on one server, in both insertion orders."""
import base64
import json
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
version = subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout
if f"Revision: {revision}" not in version:
    raise RuntimeError("unexpected sing-box revision")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise RuntimeError("unexpected EOF")
        result.extend(part)
    return bytes(result)


def exchange(proxy_port, target, marker):
    payload = marker * 4000
    errors = []
    with socket.socket() as origin:
        origin.bind((target, 0))
        origin.listen(1)
        origin.settimeout(10)
        origin_port = origin.getsockname()[1]

        def serve():
            try:
                with origin.accept()[0] as peer:
                    peer.settimeout(10)
                    data = bytearray()
                    while part := peer.recv(8192):
                        data.extend(part)
                    if data != payload:
                        raise RuntimeError(f"origin received {len(data)} bytes")
                    peer.sendall(data)
                    peer.shutdown(socket.SHUT_WR)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as client:
            client.settimeout(10)
            client.sendall(b"\x05\x01\x00")
            if exact(client, 2) != b"\x05\x00":
                raise RuntimeError("SOCKS authentication failed")
            request = b"\x05\x01\x00\x01" + socket.inet_aton(target) + origin_port.to_bytes(2, "big")
            client.sendall(request)
            reply = exact(client, 10)
            if reply[:2] != b"\x05\x00":
                raise RuntimeError(f"SOCKS connect failed: {reply!r}")
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            if exact(client, len(payload)) != payload or client.recv(1):
                raise RuntimeError("response or EOF mismatch")
        thread.join(10)
        if thread.is_alive() or errors:
            raise RuntimeError(f"origin failed: {errors!r}")


def expect_rejected(proxy_port, target):
    with socket.socket() as origin:
        origin.bind((target, 0))
        origin.listen(1)
        origin.settimeout(.2)
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as client:
            client.settimeout(10)
            client.sendall(b"\x05\x01\x00")
            if exact(client, 2) != b"\x05\x00":
                raise RuntimeError("SOCKS authentication failed")
            client.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(target) + origin.getsockname()[1].to_bytes(2, "big"))
            reply = exact(client, 10)
            if reply[:2] == b"\x05\x00":
                try:
                    client.sendall(b"incorrect route")
                    if client.recv(1):
                        raise RuntimeError("rejected route returned data")
                except ConnectionResetError:
                    pass
        try:
            peer, _ = origin.accept()
        except TimeoutError:
            return
        peer.close()
        raise RuntimeError("incorrect route reached origin")


with tempfile.TemporaryDirectory(prefix="nexus-mixed-outbounds-") as directory:
    root = pathlib.Path(directory)
    cert, key, uuid = root / "cert.pem", root / "key.pem", root / "uuid"
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f")
    uuid.chmod(0o600)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", cert, "-subj", "/CN=cover.example", "-addext", "subjectAltName=DNS:cover.example",
                    "-days", "1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ss_port, vless_port = free_port(), free_port()
    while vless_port == ss_port:
        vless_port = free_port()
    config = {"log": {"level": "error"}, "inbounds": [
        {"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": ss_port,
         "method": "2022-blake3-aes-128-gcm", "password": base64.b64encode(bytes(range(16))).decode()},
        {"type": "vless", "tag": "vless", "listen": "127.0.0.1", "listen_port": vless_port,
         "users": [{"uuid": "00010203-0405-0607-0809-0a0b0c0d0e0f"}],
         "tls": {"enabled": True, "server_name": "cover.example", "certificate_path": str(cert), "key_path": str(key)}}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        # A swapped route is rejected by the independent upstream instead of
        # reaching the same origin by the wrong protocol.
        "route": {"rules": [
            {"inbound": ["ss"], "ip_cidr": ["127.0.0.1/32"], "action": "reject"},
            {"inbound": ["vless"], "ip_cidr": ["127.0.0.2/32"], "action": "reject"}], "final": "direct"}}
    path = root / "server.json"
    path.write_text(json.dumps(config))
    subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
    upstream = subprocess.Popen(["sing-box", "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        time.sleep(.5)
        if upstream.poll() is not None:
            raise RuntimeError(f"upstream exited: {upstream.stderr.read()!r}")
        for order in (0, 1):
            for workers in (1, 2):
                proxy = subprocess.Popen([fixture, str(ss_port), str(vless_port), uuid, cert, str(order), str(workers)],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    if not select.select([proxy.stdout], [], [], 10)[0]:
                        raise RuntimeError("proxy failed to start")
                    port = int(proxy.stdout.readline())
                    exchange(port, "127.0.0.2", b"ss-")
                    exchange(port, "127.0.0.1", b"vless-")
                finally:
                    if proxy.poll() is None:
                        proxy.stdin.write("stop\n")
                        proxy.stdin.flush()
                    _, error = proxy.communicate(timeout=10)
                    if proxy.returncode:
                        raise RuntimeError(f"proxy exited {proxy.returncode}: {error}")
        # Deliberately reverse both selections to verify the upstream rejects
        # the wrong protocol for each destination.
        proxy = subprocess.Popen([fixture, str(ss_port), str(vless_port), uuid, cert, "0", "1", "reverse"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([proxy.stdout], [], [], 10)[0]:
                raise RuntimeError("negative-control proxy failed to start")
            port = int(proxy.stdout.readline())
            expect_rejected(port, "127.0.0.2")
            expect_rejected(port, "127.0.0.1")
        finally:
            if proxy.poll() is None:
                proxy.stdin.write("stop\n")
                proxy.stdin.flush()
            _, error = proxy.communicate(timeout=10)
            if proxy.returncode:
                raise RuntimeError(f"negative-control proxy exited {proxy.returncode}: {error}")
    finally:
        upstream.terminate()
        upstream.wait(timeout=10)
print(f"SS-2022 and VLESS mixed outbound routing passed against sing-box {revision}")
