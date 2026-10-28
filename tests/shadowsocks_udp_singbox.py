#!/usr/bin/env python3
"""Exercise the UDP client session against the pinned sing-box server."""
import base64
import json
import pathlib
import socket
import subprocess
import struct
import sys
import tempfile
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")

with tempfile.TemporaryDirectory(prefix="nexus-ss2022-udp-") as directory:
    for size in (16, 32):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target, socket.socket() as reserved:
            target.bind(("127.0.0.1", 0))
            target.settimeout(5)
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
            reserved.close()
            config = {"log": {"level": "warn"}, "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1",
                "listen_port": port, "method": f"2022-blake3-aes-{size*8}-gcm",
                "password": base64.b64encode(bytes(range(size))).decode()}],
                "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
            path = pathlib.Path(directory) / "server.json"
            path.write_text(json.dumps(config))
            subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
            box = subprocess.Popen(["sing-box", "run", "-c", path], stderr=subprocess.PIPE)
            peer = None
            try:
                deadline = time.monotonic()+5
                while True:
                    if box.poll() is not None:
                        raise RuntimeError(box.stderr.read().decode())
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(.02)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.connect(("127.0.0.1", port))
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 5, 0))
                    peer = subprocess.Popen([fixture, str(client.fileno()), str(size), str(target.getsockname()[1])], pass_fds=(client.fileno(),))
                    data, sender = target.recvfrom(65535)
                    if data != b"hello":
                        raise RuntimeError("request mismatch")
                    target.sendto(b"world", sender)
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
print(f"SS-2022 UDP client session with sing-box {revision} passed")
