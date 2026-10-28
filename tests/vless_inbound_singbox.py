#!/usr/bin/env python3
"""Test the in-memory inbound handshake with an independent VLESS TCP client."""
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
version = subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout
if f"Revision: {revision}" not in version:
    raise RuntimeError("unexpected sing-box revision")


def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data


def scenario(root, mode, kind):
    with socket.socket() as listener, socket.socket() as reserved:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        reserved.bind(("127.0.0.1", 0))
        proxy_port = reserved.getsockname()[1]
        reserved.close()
        config = {
            "log": {"level": "warn"},
            "inbounds": [{"type": "socks", "tag": "local", "listen": "127.0.0.1", "listen_port": proxy_port}],
            "outbounds": [{"type": "vless", "tag": "edge", "server": "127.0.0.1", "server_port": listener.getsockname()[1],
                           "uuid": "10010203-0405-0607-0809-0a0b0c0d0e0f" if mode == "reject" else "00010203-0405-0607-0809-0a0b0c0d0e0f"}],
            "route": {"final": "edge"},
        }
        path = root / "sing-box-client.json"
        path.write_text(json.dumps(config))
        subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
        peer = subprocess.Popen([fixture, str(listener.fileno()), mode, kind], pass_fds=(listener.fileno(),))
        box = subprocess.Popen(["sing-box", "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+5
            while True:
                if box.poll() is not None: raise RuntimeError(box.stderr.read().decode())
                try:
                    client = socket.create_connection(("127.0.0.1", proxy_port), timeout=.2)
                    break
                except OSError:
                    if time.monotonic() >= deadline: raise
                    time.sleep(.02)
            with client:
                client.settimeout(5)
                client.sendall(b"\x05\x01\x00")
                if exact(client,2)!=b"\x05\x00": raise RuntimeError("SOCKS greeting failed")
                addresses = {"ipv4": b"\x01\xcb\x00\x71\x05",
                             "ipv6": b"\x04" + socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
                             "domain": b"\x03\x0cexample.test"}
                client.sendall(b"\x05\x01\x00" + addresses[kind] + b"\x01\xbb")
                head = exact(client,4)
                if head[1]!=0: raise RuntimeError(f"SOCKS dial failed: {head!r}")
                exact(client,6 if head[3]==1 else 18)
                client.sendall(b"hello")
                if mode != "accept":
                    try: data=client.recv(1)
                    except ConnectionResetError: data=b""
                    if data: raise RuntimeError("failed request returned data")
                elif exact(client,5)!=b"world":
                    raise RuntimeError("inbound response mismatch")
            if peer.wait(timeout=5)!=0: raise RuntimeError(f"inbound fixture failed: {peer.returncode}")
        finally:
            if peer.poll() is None:
                peer.kill()
                peer.wait()
            box.terminate()
            try: box.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                box.kill()
                box.communicate()


with tempfile.TemporaryDirectory(prefix="nexus-vless-inbound-") as directory:
    for kind in ("ipv4", "ipv6", "domain"):
        scenario(pathlib.Path(directory), "accept", kind)
    scenario(pathlib.Path(directory), "reject", "ipv4")
    scenario(pathlib.Path(directory), "dial-fail", "ipv4")
print(f"VLESS inbound handshake with sing-box {revision} passed")
