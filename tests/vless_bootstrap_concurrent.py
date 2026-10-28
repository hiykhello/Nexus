#!/usr/bin/env python3
"""Run concurrent VLESS sessions with explicit bootstrap on two workers."""
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

binary=pathlib.Path(sys.argv[1]).resolve()
guard=pathlib.Path(sys.argv[2]).resolve()
count=16

def exact(sock, n):
    result=bytearray()
    while len(result)<n:
        chunk=sock.recv(n-len(result))
        if not chunk: raise RuntimeError("unexpected EOF")
        result.extend(chunk)
    return bytes(result)

with tempfile.TemporaryDirectory(prefix="nexus-bootstrap-concurrent-") as directory:
    root=pathlib.Path(directory); cert=root/"cert"; key=root/"key"; uuid=root/"uuid"
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,
                    "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-days","1"],
                   check=True,capture_output=True,timeout=10)
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert,key)
    stop=threading.Event(); errors=[]; queries=[]; handlers=[]
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket() as upstream, socket.socket() as reserved:
        dns.bind(("127.0.0.1",0)); dns.settimeout(.1)
        upstream.bind(("127.0.0.1",0)); upstream.listen(count); upstream.settimeout(.1)
        reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]; reserved.close()
        def dns_server():
            try:
                while not stop.is_set():
                    try: query,peer=dns.recvfrom(512)
                    except TimeoutError: continue
                    if query[12:]!=b"\x04edge\x04test\x00\x00\x01\x00\x01": raise RuntimeError("wrong DNS query")
                    queries.append(query)
                    answer=bytearray(query); answer[2:4]=b"\x81\x80"; answer[7]=1
                    answer.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                    dns.sendto(answer,peer)
            except Exception as exc: errors.append(exc)
        def handle(raw):
            try:
                raw.settimeout(8)
                with context.wrap_socket(raw,server_side=True) as tls:
                    request=exact(tls,26)
                    if request!=b"\x00"+bytes(range(16))+b"\x00\x01\x04\xd2\x01\x7f\x00\x00\x01": raise RuntimeError("wrong VLESS request")
                    tls.sendall(b"\x00\x00")
                    data=exact(tls,4096); tls.sendall(data)
            except Exception as exc: errors.append(exc)
        def accept():
            try:
                while not stop.is_set():
                    try: raw,_=upstream.accept()
                    except TimeoutError: continue
                    thread=threading.Thread(target=handle,args=(raw,)); handlers.append(thread); thread.start()
            except Exception as exc: errors.append(exc)
        dns_thread=threading.Thread(target=dns_server); peer_thread=threading.Thread(target=accept)
        dns_thread.start(); peer_thread.start()
        config=root/"config.kdl"
        config.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; disable-cache #true; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ bootstrap-resolver "boot"; server host="edge.test" port={upstream.getsockname()[1]}; authentication {{ uuid-file "{uuid}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}; }}
routing {{ default-outbound "edge"; }}
''')
        env=os.environ.copy(); env["LD_PRELOAD"]=str(guard)
        process=subprocess.Popen([binary,"run","--config",config],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+5
            while True:
                if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.2): break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            barrier=threading.Barrier(count)
            def client(index):
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=8) as sock:
                        sock.settimeout(8); sock.sendall(b"\x05\x01\x00")
                        if exact(sock,2)!=b"\x05\x00": raise RuntimeError("SOCKS negotiation failed")
                        barrier.wait(timeout=8)
                        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2")
                        if exact(sock,10)[:2]!=b"\x05\x00": raise RuntimeError("SOCKS connect failed")
                        payload=bytes([index])*4096; sock.sendall(payload)
                        if exact(sock,len(payload))!=payload: raise RuntimeError("data mismatch")
                except Exception as exc: errors.append(exc)
            clients=[threading.Thread(target=client,args=(i,)) for i in range(count)]
            for thread in clients: thread.start()
            for thread in clients: thread.join(timeout=12)
            if any(thread.is_alive() for thread in clients) or errors: raise RuntimeError(f"client errors: {errors}")
            if len(queries)!=count: raise RuntimeError(f"expected {count} DNS queries, got {len(queries)}")
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
            stop.set(); dns_thread.join(timeout=2); peer_thread.join(timeout=2)
            for thread in handlers: thread.join(timeout=9)
        diagnostics=process.stderr.read().decode()
        if process.returncode!=0 or "unexpected-system-resolver" in diagnostics or errors:
            raise RuntimeError(f"proxy exit {process.returncode}: {diagnostics}, {errors}")
print("two-worker concurrent VLESS bootstrap and transfer passed")
