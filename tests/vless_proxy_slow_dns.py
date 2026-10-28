#!/usr/bin/env python3
"""Controlled blocking system DNS with a real VLESS/TLS inbound."""
import os
import pathlib
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import time

binary, shim = (pathlib.Path(p).resolve() for p in sys.argv[1:3])
user=bytes.fromhex("000102030405060708090a0b0c0d0e0f")
with tempfile.TemporaryDirectory(prefix="nexus-vless-slow-dns-") as directory:
    root=pathlib.Path(directory)
    key,cert,keyder,certder=(root/name for name in ("key.pem","cert.pem","key.der","cert.der"))
    def openssl(*args): subprocess.run(["openssl",*map(str,args)],check=True,capture_output=True,timeout=10)
    openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,
            "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-days","1")
    openssl("pkey","-in",key,"-outform","DER","-out",keyder)
    openssl("x509","-in",cert,"-outform","DER","-out",certder)
    keyder.chmod(0o600)
    uuid=root/"uuid"; uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1",0)); port=reservation.getsockname()[1]
    config=root/"server.kdl"
    config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ vless "edge" {{
 listen host="127.0.0.1" port={port}
 authentication {{ user "client" uuid-file="{uuid}"; }}
 tls {{ certificate-file "{certder}"; private-key-file "{keyder}"; }}
}} }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
    ready_r,ready_w=os.pipe(); gate_r,gate_w=os.pipe()
    env=os.environ.copy(); env.update(LD_PRELOAD=str(shim),NEXUS_TEST_RESOLVER_READY_FD=str(ready_w),NEXUS_TEST_RESOLVER_GATE_FD=str(gate_r))
    server=subprocess.Popen([binary,"run","--config",config],env=env,pass_fds=(ready_w,gate_r),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    os.close(ready_w); os.close(gate_r)
    clients=[]
    try:
        deadline=time.monotonic()+5
        while True:
            if server.poll() is not None: raise RuntimeError(server.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.2): break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        context=ssl.create_default_context(cafile=str(cert)); context.minimum_version=ssl.TLSVersion.TLSv1_3
        def connect():
            sock=context.wrap_socket(socket.create_connection(("127.0.0.1",port),timeout=5),server_hostname="localhost")
            sock.settimeout(12); clients.append(sock); return sock
        slow=connect(); name=b"nexus-delay.test"
        started=time.monotonic()
        slow.sendall(b"\x00"+user+b"\x00\x01\x00\x50\x02"+bytes([len(name)])+name)
        if not select.select([ready_r],[],[],3)[0] or os.read(ready_r,1)!=b"x": raise RuntimeError("resolver did not enter gate")
        # A separate handshake remains responsive while the resolver is parked.
        concurrent=connect()
        if time.monotonic()-started>5: raise RuntimeError("other TLS handshake stalled")
        try:
            if slow.recv(1): raise RuntimeError("unexpected VLESS response")
        except (ConnectionResetError,ssl.SSLError): pass
        elapsed=time.monotonic()-started
        if not 8<=elapsed<=12: raise RuntimeError(f"unexpected timeout {elapsed:.2f}s")
        connect()
        server.terminate()
        try:
            server.wait(timeout=.3)
        except subprocess.TimeoutExpired: pass
        else: raise RuntimeError("server exited while system resolver still gated")
        os.write(gate_w,b"x")
        if server.wait(timeout=5)!=0: raise RuntimeError(server.stderr.read().decode())
    finally:
        for client in clients: client.close()
        if server.poll() is None:
            try: os.write(gate_w,b"x")
            except OSError: pass
            try: server.wait(timeout=5)
            except subprocess.TimeoutExpired: server.kill(); server.wait()
        os.close(ready_r); os.close(gate_w)
print("VLESS/TLS slow DNS timeout, concurrent handshake and drained stop passed")
