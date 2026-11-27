#!/usr/bin/env python3
"""Exercise TCP protocol inbounds chained to different protocol outbounds."""
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

NEXUS = pathlib.Path(sys.argv[1]).resolve()
REVISION = "824dbcfb4dd0a95921840b1737b950cde590241e"
UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"
METHOD = "2022-blake3-aes-128-gcm"
PASSWORD = base64.b64encode(bytes(range(16))).decode()
if f"Revision: {REVISION}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")


def free_ports(count):
    sockets = [socket.socket() for _ in range(count)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError(f"unexpected EOF after {len(data)} of {size} bytes")
        data.extend(part)
    return bytes(data)


def connect_when_ready(port, *processes):
    deadline = time.monotonic() + 10
    while True:
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f"process exited {process.returncode}: {process.stderr.read()!r}")
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=1)
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.03)


def stop(process, require_success=False):
    if process.poll() is None:
        process.terminate()
    try:
        _, error = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        _, error = process.communicate()
        raise RuntimeError(f"process did not stop: {error!r}")
    if require_success and process.returncode:
        raise RuntimeError(f"Nexus exit {process.returncode}: {error!r}")


def nexus_outbound(kind, port, root):
    if kind == "ss":
        return f'outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={port}; method "{METHOD}"; key-file "{root / "ss-key"}"; }}'
    return f'outbound "edge" type="vless" {{ server host="127.0.0.1" port={port}; authentication {{ uuid-file "{root / "uuid"}"; }}; tls {{ server-name "localhost"; ca-file "{root / "cert"}"; verify #true; }}; }}'


def socks_connect(port, target, *processes):
    client = connect_when_ready(port, *processes)
    client.settimeout(15)
    try:
        client.sendall(b"\x05\x01\x00")
        if exact(client, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS greeting failed")
        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target.to_bytes(2, "big"))
        head = exact(client, 4)
        if head[:2] != b"\x05\x00":
            raise RuntimeError(f"SOCKS connect failed: {head!r}")
        exact(client, 6 if head[3] == 1 else 18)
        return client
    except BaseException:
        client.close()
        raise


def scenario(root, inbound, outbound, workers, upstream_ports, upstream):
    front, socks = free_ports(2)
    if inbound == "ss":
        inbound_config = f'inbound "edge" type="shadowsocks" {{ listen host="127.0.0.1" port={front}; method "{METHOD}"; key-file "{root / "ss-key"}"; }}'
    else:
        inbound_config = f'inbound "edge" type="vless" {{ listen host="127.0.0.1" port={front}; authentication {{ user "test" uuid-file="{root / "uuid"}"; }}; tls {{ certificate-file "{root / "cert"}"; private-key-file "{root / "key"}"; }}; }}'
    outbound_config = nexus_outbound(outbound, upstream_ports[outbound], root)
    (root / "nexus.kdl").write_text(f'''schema-version 1
role "server"
workers {workers}
{inbound_config}
outbound "direct" type="direct"
{outbound_config}
routing {{ final "edge"; }}
''')
    (root / "client.kdl").write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={socks}; authentication "none"; }}
outbound "direct" type="direct"
{nexus_outbound(inbound, front, root)}
routing {{ final "edge"; }}
''')
    nexus = subprocess.Popen([NEXUS, "run", "--config", root / "nexus.kdl"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    client_proxy = subprocess.Popen([NEXUS, "run", "--config", root / "client.kdl"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        with connect_when_ready(front, nexus, client_proxy, upstream):
            pass
        with socket.socket() as origin:
            origin.bind(("127.0.0.1", 0)); origin.listen(2); origin.settimeout(15)
            with socks_connect(socks, origin.getsockname()[1], nexus, client_proxy, upstream) as client:
                client.sendall(b"start")
                with origin.accept()[0] as peer:
                    peer.settimeout(15)
                    if exact(peer, 5) != b"start":
                        raise RuntimeError("incorrect chain prefix")
                    payload = bytes(range(256)) * 8192
                    errors = []
                    def echo():
                        try:
                            time.sleep(.1)
                            remaining = len(payload)
                            while remaining:
                                data = peer.recv(min(16384, remaining))
                                if not data:
                                    raise RuntimeError("truncated upload")
                                peer.sendall(data); remaining -= len(data)
                            if peer.recv(1):
                                raise RuntimeError("missing upload EOF")
                            peer.sendall(b"late reply"); peer.shutdown(socket.SHUT_WR)
                        except Exception as exc:
                            errors.append(exc)
                    worker = threading.Thread(target=echo, daemon=True); worker.start()
                    def send():
                        try:
                            client.sendall(payload)
                        except Exception as exc:
                            errors.append(exc)
                    sender = threading.Thread(target=send, daemon=True); sender.start()
                    if exact(client, len(payload)) != payload:
                        raise RuntimeError("chain payload mismatch")
                    sender.join(15)
                    if sender.is_alive() or errors:
                        raise RuntimeError(f"upload did not finish: {errors!r}")
                    client.shutdown(socket.SHUT_WR)
                    if exact(client, 10) != b"late reply" or client.recv(1):
                        raise RuntimeError("late reply or download EOF mismatch")
                    worker.join(15)
                    if worker.is_alive() or errors:
                        raise RuntimeError(f"origin failed: {errors!r}")
            with socks_connect(socks, origin.getsockname()[1], nexus, client_proxy, upstream) as client:
                client.sendall(b"hold")
                with origin.accept()[0] as peer:
                    peer.settimeout(10)
                    if exact(peer, 4) != b"hold":
                        raise RuntimeError("incorrect cancellation prefix")
                    stop(nexus, require_success=True)
                    try:
                        data = peer.recv(1)
                    except ConnectionResetError:
                        data = b""
                    if data:
                        raise RuntimeError("origin remained open after stop")
                    try:
                        data = client.recv(1)
                    except ConnectionResetError:
                        data = b""
                    if data:
                        raise RuntimeError("client remained open after stop")
    finally:
        stop(client_proxy, require_success=True)
        if nexus.poll() is None:
            stop(nexus, require_success=True)
    print(f"{inbound} -> {outbound}, workers={workers}: transfer, delayed reply and stop passed")


with tempfile.TemporaryDirectory(prefix="nexus-stream-chains-") as directory:
    root = pathlib.Path(directory)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key",
                    "-out", root / "cert", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-days", "1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root / "key").chmod(0o600)
    (root / "uuid").write_text(UUID + "\n"); (root / "uuid").chmod(0o600)
    (root / "ss-key").write_text(PASSWORD + "\n"); (root / "ss-key").chmod(0o600)
    ss_port, vless_port = free_ports(2)
    ports = {"ss": ss_port, "vless": vless_port}
    server_config = {"log": {"level": "error"}, "inbounds": [
        {"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": ss_port,
         "method": METHOD, "password": PASSWORD},
        {"type": "vless", "listen": "127.0.0.1", "listen_port": vless_port,
         "users": [{"uuid": UUID}], "tls": {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")}}],
        "outbounds": [{"type": "direct"}]}
    (root / "upstream.json").write_text(json.dumps(server_config))
    subprocess.run(["sing-box", "check", "-c", root / "upstream.json"], check=True, capture_output=True)
    upstream = subprocess.Popen(["sing-box", "run", "-c", root / "upstream.json"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for port in ports.values():
            with connect_when_ready(port, upstream):
                pass
        for workers in (1, 2):
            for inbound in ("ss", "vless"):
                for outbound in ("ss", "vless"):
                    scenario(root, inbound, outbound, workers, ports, upstream)
    finally:
        stop(upstream)
