#!/usr/bin/env python3
"""Exercise VLESS/TLS inbound rejection with an independent TLS client."""
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile

fixture = pathlib.Path(sys.argv[1]).resolve()
user = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

with tempfile.TemporaryDirectory(prefix="nexus-vless-inbound-failures-") as directory:
    root = pathlib.Path(directory)
    key, cert = root / "key.pem", root / "cert.pem"
    key_der, cert_der = root / "key.der", root / "cert.der"
    def openssl(*args):
        subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, timeout=10)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
            "-out", cert, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1")
    openssl("pkey", "-in", key, "-outform", "DER", "-out", key_der)
    openssl("x509", "-in", cert, "-outform", "DER", "-out", cert_der)
    key_der.chmod(0o600)
    uuid = root / "uuid"; uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    context = ssl.create_default_context(cafile=str(cert))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3

    for scenario in ("wrong-user", "truncated", "dial-failure"):
        with socket.socket() as listener, socket.socket() as target:
            listener.bind(("127.0.0.1", 0)); listener.listen(1)
            target.bind(("127.0.0.1", 0))
            port = target.getsockname()[1]
            if scenario != "dial-failure":
                target.listen(1); target.settimeout(0.3)
            peer = subprocess.Popen([fixture, str(listener.fileno()), str(cert_der), str(key_der), str(uuid)],
                                    pass_fds=(listener.fileno(),))
            try:
                with socket.create_connection(listener.getsockname(), timeout=5) as raw:
                    with context.wrap_socket(raw, server_hostname="localhost") as client:
                        client.settimeout(5)
                        identity = bytes(16) if scenario == "wrong-user" else user
                        request = b"\x00" + identity + b"\x00\x01" + port.to_bytes(2, "big") + b"\x01\x7f\x00\x00\x01"
                        client.sendall(request[:8] if scenario == "truncated" else request)
                        if scenario != "truncated":
                            try:
                                if client.recv(1): raise RuntimeError(f"{scenario}: unexpected response")
                            except (ConnectionResetError, ssl.SSLError):
                                pass
                if peer.wait(timeout=5) != 6:
                    raise RuntimeError(f"{scenario}: fixture exit {peer.returncode}")
                if scenario != "dial-failure":
                    try:
                        conn, _ = target.accept()
                    except TimeoutError:
                        pass
                    else:
                        conn.close()
                        raise RuntimeError(f"{scenario}: unexpectedly dialed target")
            finally:
                if peer.poll() is None:
                    peer.kill(); peer.wait()
print("VLESS/TLS inbound wrong identity, truncated request and failed dial passed")
