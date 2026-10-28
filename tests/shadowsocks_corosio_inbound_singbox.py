#!/usr/bin/env python3
"""Exercise the async SS-2022 inbound stream through an independent sing-box client."""
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")

def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data

def scenario(root, size):
    with socket.socket() as listener, socket.socket() as reserved:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
        reserved.close()
        config = {
            "log": {"level": "warn"},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [{"type": "shadowsocks", "tag": "edge", "server": "127.0.0.1",
                           "server_port": listener.getsockname()[1],
                           "method": f"2022-blake3-aes-{size*8}-gcm",
                           "password": base64.b64encode(bytes(range(size))).decode()}],
            "route": {"final": "edge"},
        }
        path = root / "client.json"
        path.write_text(json.dumps(config))
        subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
        peer = subprocess.Popen([fixture, str(listener.fileno()), str(size)], pass_fds=(listener.fileno(),))
        box = subprocess.Popen(["sing-box", "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while True:
                if box.poll() is not None:
                    raise RuntimeError(box.stderr.read().decode())
                try:
                    client = socket.create_connection(("127.0.0.1", port), timeout=.2)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.02)
            with client:
                client.settimeout(5)
                client.sendall(b"\x05\x01\x00")
                if exact(client, 2) != b"\x05\x00":
                    raise RuntimeError("SOCKS greeting failed")
                client.sendall(b"\x05\x01\x00\x01\xcb\x00\x71\x05\x01\xbb")
                head = exact(client, 4)
                if head[1] != 0:
                    raise RuntimeError(f"SOCKS dial failed: {head!r}")
                exact(client, 6 if head[3] == 1 else 18)
                client.sendall(b"hello")
                if exact(client, 10) != b"worldagain":
                    raise RuntimeError("response mismatch")
                if client.recv(1)!=b"": raise RuntimeError("response did not close")
            if peer.wait(timeout=5) != 0:
                raise RuntimeError(f"fixture failed: {peer.returncode}")
        finally:
            if peer.poll() is None:
                peer.kill()
                peer.wait()
            box.terminate()
            try:
                box.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                box.kill()
                box.communicate()

with tempfile.TemporaryDirectory(prefix="nexus-ss2022-") as directory:
    for size in (16, 32):
        scenario(pathlib.Path(directory), size)
print(f"SS-2022 async inbound stream with sing-box {revision} passed")
