#!/usr/bin/env python3
"""Test the SS-2022 codec as a client of an independent sing-box server."""
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
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        data += chunk
    return data

def scenario(root, size):
    with socket.socket() as target, socket.socket() as reserved:
        target.bind(("127.0.0.1", 0))
        target.listen(1)
        target.settimeout(5)
        reserved.bind(("127.0.0.1", 0))
        proxy_port = reserved.getsockname()[1]
        reserved.close()
        config = {
            "log": {"level": "warn"},
            "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": proxy_port,
                          "method": f"2022-blake3-aes-{size*8}-gcm",
                          "password": base64.b64encode(bytes(range(size))).decode()}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }
        path = root / "server.json"
        path.write_text(json.dumps(config))
        subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
        box = subprocess.Popen(["sing-box", "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        peer = None
        try:
            deadline = time.monotonic() + 5
            while True:
                if box.poll() is not None:
                    raise RuntimeError(box.stderr.read().decode())
                try:
                    client = socket.create_connection(("127.0.0.1", proxy_port), timeout=.2)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.02)
            with client:
                client.setblocking(True)
                peer = subprocess.Popen([fixture, str(client.fileno()), str(size), str(target.getsockname()[1])],
                                        pass_fds=(client.fileno(),))
                with target.accept()[0] as upstream:
                    upstream.settimeout(5)
                    if exact(upstream, 10) != b"helloagain":
                        raise RuntimeError("request mismatch")
                    upstream.sendall(b"worldagain")
                if peer.wait(timeout=5) != 0:
                    raise RuntimeError(f"fixture failed: {peer.returncode}")
        finally:
            if peer is not None and peer.poll() is None:
                peer.kill()
                peer.wait()
            box.terminate()
            try:
                box.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                box.kill()
                box.communicate()

with tempfile.TemporaryDirectory(prefix="nexus-ss2022-server-") as directory:
    for size in (16, 32):
        scenario(pathlib.Path(directory), size)
print(f"SS-2022 TCP client fixture with sing-box {revision} passed")
