#!/usr/bin/env python3
"""Force an X25519 HelloRetryRequest from a configured Nexus VLESS inbound."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

nexus = pathlib.Path(sys.argv[1]).resolve()
mode = sys.argv[2] if len(sys.argv)>2 else "x25519-retry"
groups = {"x25519-retry":"P-256:X25519", "hybrid":"X25519MLKEM768", "hybrid-retry":"P-256:X25519MLKEM768"}
if mode not in groups: raise ValueError("invalid test mode")
with tempfile.TemporaryDirectory(prefix="nexus-vless-hrr-") as directory:
    root = pathlib.Path(directory)
    cert, key, uuid, trace = (root / name for name in ("cert.pem", "key.pem", "uuid", "trace"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", cert, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-days", "1"], check=True, capture_output=True, timeout=10)
    key.chmod(0o600)
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    with socket.socket() as reserved, socket.socket() as target:
        reserved.bind(("127.0.0.1", 0)); port=reserved.getsockname()[1]; reserved.close()
        target.bind(("127.0.0.1", 0)); target.listen(1); target.settimeout(8)
        config=root/"server.kdl"
        config.write_text(f'''schema-version 1
role "server"
inbounds {{ vless "edge" {{ listen host="127.0.0.1" port={port}; authentication {{ user "client" uuid-file="{uuid}"; }}; tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}; }} }}
outbounds {{ direct "direct"; }}
routing {{ final "direct"; }}
''')
        server=subprocess.Popen([nexus, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        errors=[]; payload=b"hello retry request transfer"
        def origin():
            try:
                with target.accept()[0] as conn:
                    conn.settimeout(5); received=b""
                    while len(received)<len(payload):
                        chunk=conn.recv(len(payload)-len(received))
                        if not chunk: raise RuntimeError("truncated request")
                        received+=chunk
                    if received!=payload: raise RuntimeError("wrong request")
                    conn.sendall(received); conn.shutdown(socket.SHUT_WR)
            except Exception as exc: errors.append(exc)
        worker=threading.Thread(target=origin); worker.start()
        try:
            deadline=time.monotonic()+5
            while True:
                if server.poll() is not None: raise RuntimeError(server.stderr.read().decode())
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.2): break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            request=b"\x00"+bytes.fromhex("000102030405060708090a0b0c0d0e0f")+b"\x00\x01"+target.getsockname()[1].to_bytes(2,"big")+b"\x01\x7f\x00\x00\x01"+payload
            result=subprocess.run(["openssl","s_client","-connect",f"127.0.0.1:{port}","-tls1_3",
                                   "-groups",groups[mode],"-servername","localhost","-CAfile",str(cert),
                                   "-verify_hostname","localhost","-verify_return_error","-quiet","-brief","-msg","-msgfile",str(trace)],
                                  input=request,capture_output=True,timeout=10)
            if result.returncode!=0 or result.stdout!=b"\x00\x00"+payload:
                raise RuntimeError(f"TLS relay failed: {result.returncode}, {result.stdout!r}, {result.stderr.decode()}")
            if trace.read_text().count("ServerHello") != (2 if mode.endswith("-retry") else 1):
                raise RuntimeError("unexpected number of ServerHello messages")
            expected_group="X25519MLKEM768" if mode.startswith("hybrid") else "X25519"
            if expected_group not in result.stderr.decode(): raise RuntimeError("unexpected negotiated group")
            worker.join(timeout=5)
            if worker.is_alive() or errors: raise RuntimeError(f"origin failed: {errors}")
        finally:
            server.terminate()
            try: server.wait(timeout=5)
            except subprocess.TimeoutExpired: server.kill(); server.wait()
            worker.join(timeout=9)
        if server.returncode!=0: raise RuntimeError(f"server exit: {server.returncode}")
print(f"OpenSSL {mode}, authenticated TLS and VLESS relay passed")
