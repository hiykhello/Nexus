#!/usr/bin/env python3
"""Probe the production SS-2022 tunnel and UoT v2 against pinned sing-box."""
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
version = subprocess.run(["sing-box", "version"], capture_output=True, text=True, check=True).stdout
if f"Revision: {revision}" not in version:
    raise RuntimeError("unexpected sing-box revision")

with tempfile.TemporaryDirectory(prefix="nexus-uot-") as directory, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin:
    origin.bind(("127.0.0.1", 0))
    origin.settimeout(10)
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    config = {"log": {"level": "error"}, "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
              "method": "2022-blake3-aes-128-gcm", "password": base64.b64encode(bytes(range(16))).decode()}],
              "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
    path = pathlib.Path(directory) / "config.json"
    path.write_text(json.dumps(config))
    subprocess.run(["sing-box", "check", "-c", path], capture_output=True, check=True)
    server = subprocess.Popen(["sing-box", "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    received = []
    def echo():
        try:
            for _ in range(2):
                data, peer = origin.recvfrom(65535)
                received.append(data)
                origin.sendto(data, peer)
        except Exception as exc:
            received.append(exc)
    worker = threading.Thread(target=echo, daemon=True)
    worker.start()
    try:
        time.sleep(.5)
        if server.poll() is not None:
            raise RuntimeError(f"sing-box exited: {server.stderr.read()!r}")
        for mode in ("1", "0"):
            result = subprocess.run([fixture, str(port), str(origin.getsockname()[1]), mode], capture_output=True, timeout=20)
            if result.returncode != 0:
                raise RuntimeError(f"UoT mode {mode} returned {result.returncode}: {result.stderr!r}; origin: {received!r}")
        worker.join(timeout=11)
        if received != [b"uot-probe", b"uot-probe"]:
            raise RuntimeError(f"origin failed: {received!r}")
        print("SS-2022 production tunnel UoT v2 connected and unconnected datagrams with sing-box passed")
    finally:
        server.terminate()
        server.communicate(timeout=5)
