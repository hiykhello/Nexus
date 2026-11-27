#!/usr/bin/env python3
"""Real TLS sessions exercise shared VLESS listener quota and shutdown."""
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
def exact(sock, size):
    data=bytearray()
    while len(data)<size:
        part=sock.recv(size-len(data))
        if not part: raise RuntimeError("unexpected EOF")
        data.extend(part)
    return bytes(data)
with tempfile.TemporaryDirectory(prefix="nexus-vless-limits-") as directory:
    root = pathlib.Path(directory)
    key, cert, keyder, certder = (root / name for name in ("key.pem", "cert.pem", "key.der", "cert.der"))
    def openssl(*args):
        subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True, timeout=10)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1")
    openssl("pkey", "-in", key, "-outform", "DER", "-out", keyder)
    openssl("x509", "-in", cert, "-outform", "DER", "-out", certder)
    keyder.chmod(0o600)
    uuid = root / "user"; uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0)); port=reserved.getsockname()[1]
    config = root / "server.kdl"
    config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ vless "edge" {{
 listen host="127.0.0.1" port={port}
 authentication {{ user "client" uuid-file="{uuid}"; }}
 tls {{ certificate-file "{certder}"; private-key-file "{keyder}"; }}
}} }}
outbounds {{ direct "direct"; }}
routing {{ final "direct"; }}
''')
    server = subprocess.Popen([binary, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    clients = []
    try:
        deadline = time.monotonic()+5
        while True:
            if server.poll() is not None: raise RuntimeError(server.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2): break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        context = ssl.create_default_context(cafile=str(cert))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        def connect():
            raw=socket.create_connection(("127.0.0.1", port), timeout=3)
            try: return context.wrap_socket(raw, server_hostname="localhost")
            except BaseException: raw.close(); raise
        for _ in range(64): clients.append(connect())
        try:
            extra=connect()
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError): pass
        else:
            extra.close(); raise RuntimeError("65th TLS handshake unexpectedly completed")
        # Drop half the sessions and confirm their leases become reusable.
        for client in clients[:32]: client.close()
        del clients[:32]
        deadline=time.monotonic()+3
        while True:
            try: clients.append(connect()); break
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                if time.monotonic()>=deadline: raise RuntimeError("quota was not reclaimed")
                time.sleep(.02)
        for _ in range(31): clients.append(connect())
        try:
            extra=connect()
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError): pass
        else:
            extra.close(); raise RuntimeError("reclaimed quota exceeded 64")
        for client in clients: client.close()
        clients.clear()
        # The handshake budget covers the VLESS request, not just TLS.
        deadline=time.monotonic()+3
        while True:
            try: stalled=connect(); break
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                if time.monotonic()>=deadline: raise RuntimeError("quota was not reclaimed after closing clients")
                time.sleep(.02)
        stalled.settimeout(13)
        started=time.monotonic()
        stalled.sendall(b"\x00\x00")
        try:
            if stalled.recv(1): raise RuntimeError("unexpected stalled-handshake response")
        except (ssl.SSLError, ConnectionResetError): pass
        elapsed=time.monotonic()-started
        stalled.close()
        if not 8<=elapsed<=12: raise RuntimeError(f"unexpected handshake timeout: {elapsed:.2f}s")
        # Stop while both relay directions are parked on a live target.
        with socket.socket() as target:
            target.bind(("127.0.0.1",0)); target.listen(); target.settimeout(5)
            active=connect(); clients.append(active); active.settimeout(5)
            user=bytes.fromhex("000102030405060708090a0b0c0d0e0f")
            active.sendall(b"\x00"+user+b"\x00\x01"+target.getsockname()[1].to_bytes(2,"big")+b"\x02\x09localhost")
            with target.accept()[0] as upstream:
                upstream.settimeout(5)
                if exact(active,2)!=b"\x00\x00": raise RuntimeError("missing VLESS success")
                active.sendall(b"ping")
                if exact(upstream,4)!=b"ping": raise RuntimeError("upload failed")
                upstream.sendall(b"pong")
                if exact(active,4)!=b"pong": raise RuntimeError("download failed")
                server.terminate()
                if server.wait(timeout=5)!=0: raise RuntimeError(server.stderr.read().decode())
                if upstream.recv(1)!=b"": raise RuntimeError("upstream remained open on stop")
        for client in clients:
            client.settimeout(2)
            try:
                if client.recv(1): raise RuntimeError("unexpected data on shutdown")
            except (ssl.SSLError, ConnectionResetError): pass
    finally:
        for client in clients: client.close()
        if server.poll() is None: server.kill(); server.wait()
print("two-worker VLESS/TLS shared quota, recovery, handshake deadline, domain relay and active shutdown passed")
