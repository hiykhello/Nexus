#!/usr/bin/env python3
"""Exercise a Nexus proxy server using the SS-2022 KDL configuration."""
import base64
import concurrent.futures
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")

def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size-len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)

def connect_proxy(port, destination):
    client=socket.create_connection(("127.0.0.1",port),timeout=15)
    client.settimeout(15); client.sendall(b"\x05\x01\x00")
    if exact(client,2)!=b"\x05\x00": raise RuntimeError("greeting failed")
    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+destination.to_bytes(2,"big"))
    head=exact(client,4)
    if head[1]!=0: raise RuntimeError(f"CONNECT failed: {head!r}")
    exact(client,6 if head[3]==1 else 18)
    return client

def http_response(port):
    with socket.socket() as target:
        target.bind(("127.0.0.1",0)); target.listen(1); target.settimeout(5)
        errors=[]; delivered=threading.Event()
        def origin():
            try:
                with target.accept()[0] as peer:
                    peer.settimeout(5)
                    header=b""
                    while b"\r\n\r\n" not in header:
                        header+=exact(peer,1)
                    if not header.startswith(b"POST /upload HTTP/1.1\r\n"):
                        raise RuntimeError("incorrect forwarded HTTP request")
                    peer.sendall(b"HTTP/1.1 413 Too Large\r\nContent-Length: 2\r\n\r\nno")
                    if not delivered.wait(5): raise RuntimeError("HTTP response did not reach client")
            except Exception as error: errors.append(error)
        thread=threading.Thread(target=origin); thread.start()
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=5) as client:
                client.settimeout(5)
                client.sendall((f"POST http://127.0.0.1:{target.getsockname()[1]}/upload HTTP/1.1\r\n"
                                "Host: example.test\r\nContent-Length: 1000000\r\n\r\npartial").encode())
                header=b""
                while b"\r\n\r\n" not in header: header+=exact(client,1)
                if not header.startswith(b"HTTP/1.1 413 "):
                    raise RuntimeError(f"HTTP response over SS-2022 failed: {header!r}, origin: {errors!r}")
                if exact(client,2)!=b"no": raise RuntimeError("incorrect HTTP response body")
                delivered.set()
                client.shutdown(socket.SHUT_WR)
                if client.recv(1)!=b"": raise RuntimeError("HTTP response did not end")
        finally:
            thread.join(timeout=6)
        if thread.is_alive() or errors: raise RuntimeError(f"HTTP origin failed: {errors}")

def concurrent_transfer(port):
    count=8
    payload=bytes(range(256))*8192  # 2 MiB per direction, per connection.
    reply=payload[::-1]
    with socket.socket() as target, concurrent.futures.ThreadPoolExecutor(max_workers=count*2+1) as pool:
        target.bind(("127.0.0.1",0)); target.listen(count); target.settimeout(15)
        def serve(sock):
            with sock:
                sock.settimeout(15)
                # Let the upload fill socket buffers before consuming it.
                time.sleep(.2)
                if exact(sock,len(payload))!=payload or sock.recv(1)!=b"": raise RuntimeError("large upload mismatch")
                sock.sendall(reply); sock.shutdown(socket.SHUT_WR)
        def accept_all():
            return [pool.submit(serve,target.accept()[0]) for _ in range(count)]
        def client_run():
            with connect_proxy(port,target.getsockname()[1]) as client:
                client.sendall(payload); client.shutdown(socket.SHUT_WR)
                # Delay reads so the download also encounters a slow consumer.
                time.sleep(.2)
                if exact(client,len(reply))!=reply or client.recv(1)!=b"": raise RuntimeError("large download mismatch")
        accepting=pool.submit(accept_all)
        clients=[pool.submit(client_run) for _ in range(count)]
        servers=accepting.result(timeout=30)
        for future in clients+servers: future.result(timeout=45)

def scenario(root, size, tcp_dns=False):
    with socket.socket() as target, socket.socket() as reserved, socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp_dns else socket.SOCK_DGRAM) as dns:
        target.bind(("127.0.0.1",0)); target.listen(1); target.settimeout(5)
        dns.bind(("127.0.0.1",0)); dns.settimeout(.1)
        if tcp_dns: dns.listen(32)
        stopped=threading.Event(); dns_failure=threading.Event(); dns_stall=threading.Event(); stalled=threading.Event(); dns_queries=[]; dns_errors=[]
        if size==32: dns_failure.set()
        def answer(query):
            dns_queries.append(query)
            question=query[12:]
            if question not in (b"\x04edge\x04test\x00\x00\x01\x00\x01",b"\x0ablocked-ip\x04test\x00\x00\x01\x00\x01"):
                raise RuntimeError("unexpected DNS query")
            if dns_stall.is_set(): stalled.set(); return None
            failure=dns_failure.is_set()
            reply=query[:2]+(b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" if failure else
                            b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00")+query[12:]
            if not failure:
                reply+=b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00"+(b"\x02" if question.startswith(b"\x0a") else b"\x01")
            return reply
        def serve_dns():
            try:
                while not stopped.is_set():
                    try:
                        if tcp_dns:
                            conn,_=dns.accept()
                            with conn:
                                conn.settimeout(5)
                                length=int.from_bytes(exact(conn,2),"big")
                                reply=answer(exact(conn,length))
                                if reply: conn.sendall(len(reply).to_bytes(2,"big")+reply)
                        else:
                            query,peer=dns.recvfrom(2048)
                            reply=answer(query)
                            if reply: dns.sendto(reply,peer)
                    except TimeoutError: continue
            except Exception as exc: dns_errors.append(exc)
        dns_thread=threading.Thread(target=serve_dns,daemon=True); dns_thread.start()
        reserved.bind(("127.0.0.1",0)); upstream_port=reserved.getsockname()[1]; reserved.close()
        config={"log":{"level":"warn"},
                "inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":upstream_port,
                             "method":f"2022-blake3-aes-{size*8}-gcm",
                             "password":base64.b64encode(bytes(range(size))).decode()}],
                "outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
        path=root / "server.json"; path.write_text(json.dumps(config))
        subprocess.run(["sing-box","check","-c",path],check=True,capture_output=True)
        box=subprocess.Popen(["sing-box","run","-c",path],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        proxy=None
        try:
            deadline=time.monotonic()+5
            while True:
                if box.poll() is not None: raise RuntimeError(box.stderr.read().decode())
                try:
                    check=socket.create_connection(("127.0.0.1",upstream_port),timeout=.2); check.close(); break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            with socket.socket() as local:
                local.bind(("127.0.0.1",0)); port=local.getsockname()[1]
            key=root / "key"; key.write_text(base64.b64encode(bytes(range(size))).decode()+"\n"); key.chmod(0o600)
            (root / "deny.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="domain-suffix" value="blocked.test"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
            conf=root / "nexus.kdl"
            transport="tcp" if tcp_dns else "udp"
            bootstrap=(f'dns {{ server "boot" type="{transport}" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; disable-cache #true; }}' if size==32 else '')
            host="edge.test" if size==32 else "127.0.0.1"
            resolver='bootstrap-resolver "boot";' if size==32 else ''
            conf.write_text(f'''schema-version 1
role "client"
{bootstrap}
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
outbound "ss" type="shadowsocks" {{ server host="{host}" port={upstream_port}; {resolver} method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }}
routing {{ rulesets {{ "deny" path="deny.kdl" format="kdl"; }}; rules {{ - rule-set="deny" to="reject"; }}; final "ss"; }}
''')
            for invalid, mode in [("AAAA",0o600), (base64.b64encode(bytes(range(size))).decode(),0o644)]:
                key.write_text(invalid); key.chmod(mode)
                failed=subprocess.run([fixture,"run","--config",conf],capture_output=True,text=True,timeout=5)
                if failed.returncode==0: raise RuntimeError("invalid key accepted")
                with socket.socket() as probe:
                    if probe.connect_ex(("127.0.0.1",port))==0: raise RuntimeError("listener started on invalid key")
            key.write_text(base64.b64encode(bytes(range(size))).decode()+"\n"); key.chmod(0o600)
            proxy=subprocess.Popen([fixture,"run","--config",conf],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            deadline=time.monotonic()+5
            while True:
                if proxy.poll() is not None: raise RuntimeError(proxy.stderr.read())
                try:
                    check=socket.create_connection(("127.0.0.1",port),timeout=.2); check.close(); break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            for destination in (b"\x03\x0cblocked.test",b"\x01\x7f\x00\x00\x02"):
                before=len(dns_queries)
                with socket.create_connection(("127.0.0.1",port),timeout=5) as blocked:
                    blocked.settimeout(5); blocked.sendall(b"\x05\x01\x00")
                    if exact(blocked,2)!=b"\x05\x00": raise RuntimeError("greeting failed")
                    blocked.sendall(b"\x05\x01\x00"+destination+target.getsockname()[1].to_bytes(2,"big"))
                    if exact(blocked,4)[1]!=2: raise RuntimeError("blocked target was not rejected")
                if len(dns_queries)!=before: raise RuntimeError("blocked target triggered bootstrap DNS")
            if size==32:
                with socket.create_connection(("127.0.0.1",port),timeout=5) as rejected:
                    rejected.settimeout(5); rejected.sendall(b"\x05\x01\x00")
                    if exact(rejected,2)!=b"\x05\x00": raise RuntimeError("greeting failed")
                    rejected.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+target.getsockname()[1].to_bytes(2,"big"))
                    if exact(rejected,4)[1]==0: raise RuntimeError("failed bootstrap unexpectedly connected")
                if not dns_queries: raise RuntimeError("bootstrap resolver not queried")
                dns_failure.clear()
                before=len(dns_queries)
                with socket.create_connection(("127.0.0.1",port),timeout=5) as blocked:
                    blocked.settimeout(5); blocked.sendall(b"\x05\x01\x00")
                    if exact(blocked,2)!=b"\x05\x00": raise RuntimeError("greeting failed")
                    blocked.sendall(b"\x05\x01\x00\x03\x0fblocked-ip.test"+target.getsockname()[1].to_bytes(2,"big"))
                    if exact(blocked,4)[1]!=2: raise RuntimeError("resolved blocked IP was not rejected")
                if len(dns_queries)!=before+1 or dns_queries[-1][12]!=10:
                    raise RuntimeError("blocked resolved address triggered node resolution")
            http_response(port)
            with connect_proxy(port,target.getsockname()[1]) as client:
                client.sendall(b"helloagain"); client.shutdown(socket.SHUT_WR)
                with target.accept()[0] as upstream:
                    upstream.settimeout(5)
                    if exact(upstream,10)!=b"helloagain" or upstream.recv(1)!=b"": raise RuntimeError("upload failed")
                    upstream.sendall(b"worldagain"); upstream.shutdown(socket.SHUT_WR)
                    if exact(client,10)!=b"worldagain" or client.recv(1)!=b"": raise RuntimeError("download failed")
            concurrent_transfer(port)
            pending=None
            if size==32 and not tcp_dns:
                dns_stall.set(); stalled.clear()
                with socket.create_connection(("127.0.0.1",port),timeout=5) as timeout_client:
                    timeout_client.settimeout(15); timeout_client.sendall(b"\x05\x01\x00")
                    if exact(timeout_client,2)!=b"\x05\x00": raise RuntimeError("greeting failed")
                    start=time.monotonic()
                    timeout_client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+target.getsockname()[1].to_bytes(2,"big"))
                    if not stalled.wait(5): raise RuntimeError("bootstrap timeout query not observed")
                    if exact(timeout_client,4)[1]==0: raise RuntimeError("timed-out bootstrap connected")
                    if not 8<=time.monotonic()-start<=14: raise RuntimeError("unexpected bootstrap deadline")
                stalled.clear()
                dns_stall.set()
                pending=socket.create_connection(("127.0.0.1",port),timeout=5); pending.settimeout(5)
                pending.sendall(b"\x05\x01\x00")
                if exact(pending,2)!=b"\x05\x00": raise RuntimeError("greeting failed")
                pending.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+target.getsockname()[1].to_bytes(2,"big"))
                if not stalled.wait(5): raise RuntimeError("bootstrap query did not stall")
                dns_stall.clear()
            # Stop with both relay directions waiting on live sockets.
            with connect_proxy(port,target.getsockname()[1]) as client:
                client.sendall(b"x")
                with target.accept()[0] as upstream:
                    upstream.settimeout(5)
                    if exact(upstream,1)!=b"x": raise RuntimeError("stop setup failed")
                    proxy.terminate()
                    out,err=proxy.communicate(timeout=5)
                    if proxy.returncode!=0: raise RuntimeError(f"proxy exit {proxy.returncode}: {err}")
                    proxy=None
                    if client.recv(1)!=b"" or upstream.recv(1)!=b"": raise RuntimeError("stop did not close relay")
            if pending:
                if pending.recv(1)!=b"": raise RuntimeError("stop did not close pending DNS session")
                pending.close()
            if dns_errors or (size==32 and not dns_queries) or (size==16 and dns_queries):
                raise RuntimeError(f"unexpected DNS behavior: {dns_errors}, {len(dns_queries)} queries")
        finally:
            if proxy is not None:
                proxy.terminate()
                try: out,err=proxy.communicate(timeout=5)
                except subprocess.TimeoutExpired: proxy.kill(); out,err=proxy.communicate()
                if proxy.returncode!=0: raise RuntimeError(f"proxy exit {proxy.returncode}: {err}")
            box.terminate()
            try: box.communicate(timeout=5)
            except subprocess.TimeoutExpired: box.kill(); box.communicate()
            stopped.set(); dns_thread.join(timeout=2)

with tempfile.TemporaryDirectory(prefix="nexus-ss2022-proxy-") as directory:
    for size in (16,32): scenario(pathlib.Path(directory),size)
    scenario(pathlib.Path(directory),32,tcp_dns=True)
print(f"SS-2022 Nexus KDL with sing-box {revision} passed")
