#!/usr/bin/env python3
"""Exercise independent simultaneous VLESS/TLS streams through the real CLI."""
import concurrent.futures
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

binary=pathlib.Path(sys.argv[1]).resolve()
count=32
size=256*1024
user=bytes.fromhex("000102030405060708090a0b0c0d0e0f")
def exact(sock, size):
    data=bytearray()
    while len(data)<size:
        part=sock.recv(min(65536,size-len(data)))
        if not part: raise RuntimeError("unexpected EOF")
        data.extend(part)
    return bytes(data)
with tempfile.TemporaryDirectory(prefix="nexus-vless-concurrent-") as directory:
    root=pathlib.Path(directory)
    key,cert,keyder,certder=(root/name for name in ("key.pem","cert.pem","key.der","cert.der"))
    def openssl(*args): subprocess.run(["openssl",*map(str,args)],check=True,capture_output=True,timeout=10)
    openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,"-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-days","1")
    openssl("pkey","-in",key,"-outform","DER","-out",keyder)
    openssl("x509","-in",cert,"-outform","DER","-out",certder)
    keyder.chmod(0o600)
    uuid=root/"uuid"; uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    with socket.socket() as reservation, socket.socket() as target:
        reservation.bind(("127.0.0.1",0)); port=reservation.getsockname()[1]; reservation.close()
        target.bind(("127.0.0.1",0)); target.listen(count); target.settimeout(10)
        config=root/"server.kdl"
        config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ vless "edge" {{ listen host="127.0.0.1" port={port}; authentication {{ user "client" uuid-file="{uuid}"; }}; tls {{ certificate-file "{certder}"; private-key-file "{keyder}"; }}; }} }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
        server=subprocess.Popen([binary,"run","--config",config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        origin_errors=[]; threads=[]; barrier=threading.Barrier(count)
        def origin(conn):
            try:
                with conn:
                    conn.settimeout(10)
                    remaining=size
                    while remaining:
                        data=conn.recv(min(16384,remaining))
                        if not data: raise RuntimeError("truncated upload")
                        conn.sendall(data); remaining-=len(data)
            except Exception as error: origin_errors.append(error)
        def accept_all():
            try:
                for _ in range(count):
                    conn,_=target.accept(); thread=threading.Thread(target=origin,args=(conn,)); threads.append(thread); thread.start()
            except Exception as error: origin_errors.append(error)
        acceptor=threading.Thread(target=accept_all)
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
            acceptor.start()
            def client(index):
                payload=bytes([index])*size
                with context.wrap_socket(socket.create_connection(("127.0.0.1",port),timeout=10),server_hostname="localhost") as stream:
                    stream.settimeout(15)
                    stream.sendall(b"\x00"+user+b"\x00\x01"+target.getsockname()[1].to_bytes(2,"big")+b"\x01\x7f\x00\x00\x01")
                    if exact(stream,2)!=b"\x00\x00": raise RuntimeError("bad VLESS response")
                    barrier.wait(timeout=15)
                    # Distinct per-stream data detects crossed sessions.
                    stream.sendall(payload)
                    if exact(stream,size)!=payload: raise RuntimeError(f"stream {index} corrupted")
            with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
                futures=[pool.submit(client,i) for i in range(count)]
                for future in futures: future.result(timeout=30)
            acceptor.join(timeout=10)
            for thread in threads: thread.join(timeout=10)
            if acceptor.is_alive() or any(t.is_alive() for t in threads) or origin_errors:
                raise RuntimeError(f"origin failure: {origin_errors}")
            server.terminate()
            if server.wait(timeout=5)!=0: raise RuntimeError(server.stderr.read().decode())
        finally:
            if server.poll() is None: server.kill(); server.wait()
            if acceptor.ident is not None: acceptor.join(timeout=11)
            for thread in threads: thread.join(timeout=11)
print("32 concurrent VLESS/TLS streams preserved independent bidirectional data")
