#!/usr/bin/env python3
"""Exercise Nexus HTTP/2 over a verified OpenSSL TLS connection."""
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile

fixture = pathlib.Path(sys.argv[1]).resolve()
def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
def frame(kind, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes((kind, flags)) + stream.to_bytes(4, "big") + payload
def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RuntimeError("truncated HTTP/2 frame")
        data.extend(chunk)
    return bytes(data)

with tempfile.TemporaryDirectory(prefix="nexus-h2-tls-") as directory:
    root = pathlib.Path(directory)
    key, key_der, cert, cert_der = (root / name for name in ("key.pem", "key.der", "cert.pem", "cert.der"))
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1")
    run("openssl", "pkey", "-in", str(key), "-outform", "DER", "-out", str(key_der))
    run("openssl", "x509", "-in", str(cert), "-outform", "DER", "-out", str(cert_der))
    for mode in ("get", "pause", "pause_output", "pause_multi", "reset_paused", "multi", "peer", "truncated", "stale"):
        pause = mode in ("pause", "pause_output", "pause_multi", "reset_paused")
        multi = mode == "multi"
        pause_multi = mode in ("pause_multi", "reset_paused")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            server = subprocess.Popen([fixture, cert_der, key_der, str(listener.fileno())] + ([mode] if mode != "get" else []), pass_fds=(listener.fileno(),))
            try:
                context = ssl.create_default_context(cafile=str(cert))
                context.set_alpn_protocols(["h2"])
                with context.wrap_socket(socket.create_connection(listener.getsockname(), timeout=5), server_hostname="localhost", suppress_ragged_eofs=False) as client:
                    if client.selected_alpn_protocol() != "h2":
                        raise RuntimeError("h2 ALPN not negotiated")
                    # Indexed :method GET, :scheme https and :path /; literal :authority.
                    headers = (b"\x83" if pause else b"\x82") + b"\x87\x84\x01\x09localhost"
                    wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0)
                    if pause_multi:
                        wire += frame(1, 5, 1, b"\x82\x87\x84\x01\x09localhost")
                        wire += frame(1, 4, 3, headers) + frame(0, 1, 3, b"upload")
                        if mode == "reset_paused": wire += frame(1, 5, 5, b"\x82\x87\x84\x01\x09localhost")
                    else:
                        wire += frame(1, 4 if pause else 5, 1, headers) + (frame(0, 1, 1, b"upload") if pause else b"")
                        wire += frame(1, 5, 3, headers) if multi else b""
                    for start in range(0, len(wire), 7):
                        client.sendall(wire[start:start+7])
                    bodies = {1: bytearray(), 5: bytearray()} if mode == "reset_paused" else {1: bytearray(), 3: bytearray()} if multi or pause_multi else {1: bytearray()}
                    statuses = set()
                    finished = set()
                    goaway = []
                    reset = False
                    while len(finished) < len(bodies) or (multi and len(goaway) < 2) or (mode == "reset_paused" and not reset):
                        header = exact(client, 9)
                        length = int.from_bytes(header[:3], "big")
                        kind, flags = header[3:5]
                        stream = int.from_bytes(header[5:9], "big") & 0x7fffffff
                        payload = exact(client, length)
                        if kind == 7:
                            goaway.append(int.from_bytes(payload[:4], "big") & 0x7fffffff)
                        if kind == 3 and stream == 3 and payload == b"\x00\x00\x00\x08": reset = True
                        if kind == 1 and stream in bodies and payload == b"\x88":
                            statuses.add(stream)  # HPACK static :status 200
                        if kind == 0 and stream in bodies:
                            bodies[stream].extend(payload)
                            if flags & 1:
                                finished.add(stream)
                    if statuses != set(bodies) or any(body != b"hello h2" for body in bodies.values()):
                        raise RuntimeError(f"unexpected responses statuses={statuses}, bodies={bodies!r}")
                    if mode == "peer":
                        client.unwrap().close()
                    if mode == "stale":
                        try:
                            client.unwrap()
                        except (ssl.SSLError, OSError):
                            pass
                        else:
                            raise RuntimeError("expected abort after stale close was rejected")
                    if mode == "truncated":
                        os.close(client.detach())
                    if multi and (goaway != [0x7fffffff, 3] or client.recv(1) != b""):
                        raise RuntimeError(f"incorrect GOAWAY or TLS close: {goaway}")
                code = server.wait(timeout=5)
                if code:
                    raise RuntimeError(f"server exited {code}")
            finally:
                if server.poll() is None:
                    server.kill()
                    server.wait()
    for mode in ("timeout", "cancel"):
        with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                server = subprocess.Popen([fixture, cert_der, key_der, str(listener.fileno()), mode], pass_fds=(listener.fileno(),))
                try:
                    context = ssl.create_default_context(cafile=str(cert))
                    context.set_alpn_protocols(["h2"])
                    with context.wrap_socket(socket.create_connection(listener.getsockname(), timeout=5), server_hostname="localhost") as client:
                        if client.selected_alpn_protocol() != "h2" or server.wait(timeout=8):
                            raise RuntimeError("idle TLS connection did not complete after timeout or cancellation")
                finally:
                    if server.poll() is None:
                        server.kill()
                        server.wait()
    for mode in ("curl", "head"):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            server = subprocess.Popen([fixture, cert_der, key_der, str(listener.fileno()), mode], pass_fds=(listener.fileno(),))
            try:
                result = subprocess.run(["curl", "--silent", "--show-error", "--http2", "--noproxy", "*", "--cacert", str(cert),
                                         "--resolve", f"localhost:{port}:127.0.0.1", "--write-out", "\n%{http_version}\n%{content_type}",
                                         f"https://localhost:{port}/"] + (["--head"] if mode == "head" else []), capture_output=True, timeout=8)
                code = server.wait(timeout=5)
                expected = b"hello h2\n2\ntext/plain" if mode == "curl" else None
                valid = result.stdout == expected if expected is not None else (
                    result.stdout.startswith(b"HTTP/2 200") and b"content-length: 8\r\n" in result.stdout.lower()
                    and result.stdout.endswith(b"\n2\ntext/plain"))
                if code or result.returncode or not valid:
                    raise RuntimeError(f"curl={result.returncode} server={code} out={result.stdout!r} err={result.stderr!r}")
            finally:
                if server.poll() is None:
                    server.kill()
                    server.wait()
print("HTTP/2 requests, multiplexing and TLS close in both directions truncation and stale-close rejection cancellation and curl interoperability passed")
