#!/usr/bin/env python3
"""Capture an independent OpenSSL TLS 1.3 ClientHello and feed the server parser."""
import pathlib
import socket
import subprocess
import sys
import tempfile

fixture = pathlib.Path(sys.argv[1]).resolve()

def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("truncated OpenSSL ClientHello")
        data.extend(chunk)
    return bytes(data)

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    client = subprocess.Popen(["openssl", "s_client", "-connect", f"127.0.0.1:{listener.getsockname()[1]}",
                               "-tls1_3", "-servername", "example.com"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        with listener.accept()[0] as peer:
            peer.settimeout(5)
            header = exact(peer, 5)
            payload = exact(peer, int.from_bytes(header[3:5], "big"))
        with tempfile.TemporaryDirectory(prefix="nexus-client-hello-") as directory:
            path = pathlib.Path(directory) / "clienthello.bin"
            path.write_bytes(header + payload)
            subprocess.run([fixture, path], check=True, timeout=5)
    finally:
        client.kill()
        client.wait(timeout=5)
