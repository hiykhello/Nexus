#!/usr/bin/env python3
"""Exercise the configured hybrid VLESS outbound against an OpenSSL TLS server."""
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

nexus = pathlib.Path(sys.argv[1]).resolve()
exchange = sys.argv[2] if len(sys.argv) > 2 else "x25519-mlkem768"
if exchange not in ("x25519-mlkem768", "x25519-mlkem768-only"): raise ValueError("invalid key exchange")

def exact(stream, length):
    result = bytearray()
    while len(result) < length:
        if not select.select([stream], [], [], 8)[0]:
            raise TimeoutError("timed out waiting for data")
        part = stream.read(length - len(result)) if hasattr(stream, "read") else stream.recv(length - len(result))
        if not part:
            raise RuntimeError("unexpected EOF")
        result.extend(part)
    return bytes(result)

with tempfile.TemporaryDirectory(prefix="nexus-vless-hybrid-openssl-") as directory:
    root = pathlib.Path(directory)
    cert, key, uuid = (root / name for name in ("cert.pem", "key.pem", "uuid"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", cert, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-days", "1"], check=True, capture_output=True, timeout=10)
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n")
    uuid.chmod(0o600)
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0)); upstream_port = reserved.getsockname()[1]
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0)); port = reserved.getsockname()[1]
    server = subprocess.Popen(["openssl", "s_server", "-accept", f"127.0.0.1:{upstream_port}",
                               "-cert", cert, "-key", key, "-tls1_3", "-groups", "X25519MLKEM768",
                               "-quiet", "-brief", "-naccept", "1"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    # Observe the listener without consuming the server's single accepted connection.
    deadline = time.monotonic() + 5
    while True:
        if server.poll() is not None: raise RuntimeError(server.stderr.read().decode())
        listeners = pathlib.Path("/proc/net/tcp").read_text().splitlines()[1:]
        if any(row.split()[1] == f"0100007F:{upstream_port:04X}" and row.split()[3] == "0A" for row in listeners): break
        if time.monotonic() >= deadline:
            server.kill(); server.wait()
            raise TimeoutError("OpenSSL listener did not start")
        time.sleep(.02)
    config = root / "proxy.kdl"
    config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={upstream_port}; authentication {{ uuid-file "{uuid}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; key-exchange "{exchange}"; }}; }}
routing {{ final "edge"; }}
''')
    proxy = subprocess.Popen([nexus, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            if proxy.poll() is not None: raise RuntimeError(proxy.stderr.read().decode())
            if server.poll() is not None: raise RuntimeError(server.stderr.read().decode())
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=.2)
                break
            except OSError:
                if time.monotonic() >= deadline: raise
                time.sleep(.02)
        with client:
            client.settimeout(8)
            client.sendall(b"\x05\x01\x00")
            if exact(client, 2) != b"\x05\x00": raise RuntimeError("SOCKS negotiation failed")
            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2")
            request = exact(server.stdout, 26)
            expected = b"\x00" + bytes(range(16)) + b"\x00\x01\x04\xd2\x01\x7f\x00\x00\x01"
            if request != expected: raise RuntimeError(f"unexpected VLESS request: {request!r}")
            server.stdin.write(b"\x00\x00")
            response = exact(client, 10)
            if response[:2] != b"\x05\x00": raise RuntimeError(f"SOCKS connect failed: {response!r}")
            client.sendall(b"client to OpenSSL")
            if exact(server.stdout, 17) != b"client to OpenSSL": raise RuntimeError("incorrect upstream payload")
            server.stdin.write(b"OpenSSL to client")
            if exact(client, 17) != b"OpenSSL to client": raise RuntimeError("incorrect downstream payload")
        proxy.terminate()
        proxy.wait(timeout=5)
        server.wait(timeout=5)
        diagnostics = server.stderr.read().decode()
        if "X25519MLKEM768" not in diagnostics: raise RuntimeError(f"unexpected TLS group: {diagnostics}")
        if proxy.returncode != 0 or server.returncode != 0:
            raise RuntimeError(f"process exit: proxy={proxy.returncode}, OpenSSL={server.returncode}: {diagnostics}")
    finally:
        for process in (proxy, server):
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
print("OpenSSL hybrid TLS and VLESS outbound transfer passed")
