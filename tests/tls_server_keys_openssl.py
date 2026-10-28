#!/usr/bin/env python3
"""OpenSSL decrypts a server handshake record built by Nexus."""
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
            raise RuntimeError("unexpected client EOF")
        data.extend(chunk)
    return bytes(data)

with socket.socket() as listener, tempfile.TemporaryDirectory(prefix="nexus-server-keys-") as directory:
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    client = subprocess.Popen(["openssl", "s_client", "-connect", f"127.0.0.1:{listener.getsockname()[1]}",
                               "-tls1_3", "-groups", "X25519", "-ciphersuites", sys.argv[2], "-msg"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with listener.accept()[0] as peer:
            peer.settimeout(5)
            header = exact(peer, 5)
            payload = exact(peer, int.from_bytes(header[3:5], "big"))
            offer = pathlib.Path(directory) / "offer.bin"
            response = pathlib.Path(directory) / "response.bin"
            offer.write_bytes(header + payload)
            subprocess.run([fixture, offer, response], check=True, timeout=5)
            peer.sendall(response.read_bytes())
            peer.shutdown(socket.SHUT_WR)
            # Let OpenSSL consume the flight before closing the deliberately incomplete handshake.
            while peer.recv(4096):
                pass
        stdout, stderr = client.communicate(timeout=5)
        if b"EncryptedExtensions" not in stdout:
            raise RuntimeError(f"OpenSSL did not decrypt EncryptedExtensions: {stdout!r} {stderr!r}")
        print("OpenSSL decrypted Nexus server handshake record")
    finally:
        if client.poll() is None:
            client.kill()
            client.wait(timeout=5)
