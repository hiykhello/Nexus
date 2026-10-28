#!/usr/bin/env python3
"""Exercise the SS-2022 Server API with an independent sing-box client."""
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

fixture=pathlib.Path(sys.argv[1]).resolve()
revision="824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box","version"],check=True,capture_output=True,text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")
def exact(sock,size):
    data=bytearray()
    while len(data)<size:
        part=sock.recv(size-len(data))
        if not part: raise RuntimeError("unexpected EOF")
        data.extend(part)
    return bytes(data)
def connect_proxy(port, destination, address=b"\x7f\x00\x00\x01"):
    client=socket.create_connection(("127.0.0.1",port),timeout=15)
    client.settimeout(15); client.sendall(b"\x05\x01\x00")
    if exact(client,2)!=b"\x05\x00": raise RuntimeError("greeting failed")
    client.sendall(b"\x05\x01\x00\x01"+address+destination.to_bytes(2,"big"))
    head=exact(client,4)
    if head[1]: raise RuntimeError("connect failed")
    exact(client,6 if head[3]==1 else 18)
    return client

def concurrent_transfer(port):
    count=8
    payload=bytes(range(256))*8192
    reply=payload[::-1]
    with socket.socket() as target, concurrent.futures.ThreadPoolExecutor(max_workers=count*2+1) as pool:
        target.bind(("127.0.0.1",0)); target.listen(count); target.settimeout(15)
        def serve(sock):
            with sock:
                sock.settimeout(30); time.sleep(.2)
                if exact(sock,len(payload))!=payload: raise RuntimeError("large upload mismatch")
                sock.sendall(reply)
        def accept_all():
            return [pool.submit(serve,target.accept()[0]) for _ in range(count)]
        def client_run():
            with connect_proxy(port,target.getsockname()[1]) as client:
                client.settimeout(30); client.sendall(payload); time.sleep(.2)
                if exact(client,len(reply))!=reply: raise RuntimeError("large download mismatch")
        accepting=pool.submit(accept_all)
        clients=[pool.submit(client_run) for _ in range(count)]
        try: servers=accepting.result(timeout=30)
        except Exception as exc:
            failures=[repr(f.exception()) for f in clients if f.done() and f.exception()]
            raise RuntimeError(f"accept failed; completed client errors: {failures}") from exc
        for future in clients+servers: future.result(timeout=45)

def scenario(root,size,workers):
    def free_port():
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0)); return sock.getsockname()[1]
    port=free_port(); second_port=free_port()
    while second_port==port: second_port=free_port()
    key=root/"key"; key.write_text(base64.b64encode(bytes(range(size))).decode()+"\n"); key.chmod(0o600)
    (root/"deny.kdl").write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
    config_path=root/"server.kdl"
    config_path.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{
  shadowsocks "a" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }}
  shadowsocks "b" {{ listen host="127.0.0.1" port={second_port}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }}
}}
outbounds {{ direct "direct"; block "reject"; }}
routing {{ rule-set "deny" path="deny.kdl" format="kdl"; rule kind="rule-set" value="deny" outbound="reject"; default-outbound "direct"; }}
''')
    for invalid,mode in [("AAAA",0o600),(base64.b64encode(bytes(range(size))).decode(),0o644)]:
        key.write_text(invalid); key.chmod(mode)
        bad=subprocess.run([fixture,"run","--config",config_path],capture_output=True,timeout=5)
        if bad.returncode==0: raise RuntimeError("bad key accepted")
        for p in (port,second_port):
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1",p))==0: raise RuntimeError("listened with bad key")
    key.write_text(base64.b64encode(bytes(range(size))).decode()+"\n"); key.chmod(0o600)
    proxy=subprocess.Popen([fixture,"run","--config",config_path],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    box=None
    try:
        deadline=time.monotonic()+5
        while True:
            if proxy.poll() is not None: raise RuntimeError(proxy.stderr.read())
            try: check=socket.create_connection(("127.0.0.1",port),timeout=.2); check.close(); break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        with socket.socket() as target, socket.socket() as reserved:
            target.bind(("127.0.0.1",0)); target.listen(8); target.settimeout(5)
            wire=subprocess.run([fixture.with_name("nexus-shadowsocks-replay-wire"),str(size),str(target.getsockname()[1])],check=True,capture_output=True).stdout
            with socket.create_connection(("127.0.0.1",port),timeout=5) as first:
                first.sendall(wire)
                with target.accept()[0] as accepted:
                    for index in range(8):
                        with socket.create_connection(("127.0.0.1",port if index%2==0 else second_port),timeout=5) as duplicate:
                            duplicate.settimeout(5); duplicate.sendall(wire)
                            try: result=duplicate.recv(1)
                            except ConnectionResetError: pass
                            else: raise RuntimeError(f"replay did not reset: {result!r}")
                    target.settimeout(.1)
                    try: extra,_=target.accept()
                    except TimeoutError: pass
                    else: extra.close(); raise RuntimeError("replay reached target")
                    target.settimeout(5)
            # Race the same new salt across both listeners; one request may dial.
            raced=subprocess.run([fixture.with_name("nexus-shadowsocks-replay-wire"),str(size),str(target.getsockname()[1]),"100"],check=True,capture_output=True).stdout
            barrier=threading.Barrier(16)
            def race(index):
                with socket.create_connection(("127.0.0.1",port if index%2==0 else second_port),timeout=5) as sock:
                    sock.settimeout(1); barrier.wait(timeout=5); sock.sendall(raced)
                    try: result=sock.recv(1)
                    except ConnectionResetError: return "reset"
                    except TimeoutError: return "accepted"
                    raise RuntimeError(f"unexpected replay result: {result!r}")
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                futures=[pool.submit(race,index) for index in range(16)]
                target.settimeout(5)
                with target.accept()[0] as accepted:
                    outcomes=[future.result(timeout=8) for future in futures]
                    if outcomes.count("accepted")!=1 or outcomes.count("reset")!=15:
                        raise RuntimeError(f"concurrent replay outcomes: {outcomes!r}")
                    target.settimeout(.2)
                    try: extra,_=target.accept()
                    except TimeoutError: pass
                    else: extra.close(); raise RuntimeError("concurrent replay reached target")
                target.settimeout(5)
            reserved.bind(("127.0.0.1",0)); socks_port=reserved.getsockname()[1]; reserved.close()
            config={"log":{"level":"warn"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":socks_port}],
                    "outbounds":[{"type":"shadowsocks","tag":"edge","server":"127.0.0.1","server_port":port,
                                  "method":f"2022-blake3-aes-{size*8}-gcm","password":base64.b64encode(bytes(range(size))).decode()}],
                    "route":{"final":"edge"}}
            path=root/"client.json"; path.write_text(json.dumps(config))
            subprocess.run(["sing-box","check","-c",path],check=True,capture_output=True)
            box=subprocess.Popen(["sing-box","run","-c",path],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            deadline=time.monotonic()+5
            while True:
                if box.poll() is not None: raise RuntimeError(box.stderr.read().decode())
                try: client=socket.create_connection(("127.0.0.1",socks_port),timeout=.2); break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            with client:
                client.settimeout(5); client.sendall(b"\x05\x01\x00")
                if exact(client,2)!=b"\x05\x00": raise RuntimeError("greeting failed")
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+target.getsockname()[1].to_bytes(2,"big"))
                head=exact(client,4)
                if head[1]: raise RuntimeError("connect failed")
                exact(client,6 if head[3]==1 else 18)
                client.sendall(b"hello")
                with target.accept()[0] as upstream:
                    upstream.settimeout(5)
                    if exact(upstream,5)!=b"hello": raise RuntimeError("upload mismatch")
                    upstream.sendall(b"world"); upstream.shutdown(socket.SHUT_WR)
                    if exact(client,5)!=b"world": raise RuntimeError("download mismatch")
            with socket.socket() as blocked_target:
                blocked_target.bind(("127.0.0.2",0)); blocked_target.listen(1); blocked_target.settimeout(.2)
                with connect_proxy(socks_port,blocked_target.getsockname()[1],b"\x7f\x00\x00\x02") as blocked:
                    blocked.sendall(b"blocked"); blocked.settimeout(5)
                    try: closed=blocked.recv(1)
                    except ConnectionResetError: closed=b""
                    if closed!=b"": raise RuntimeError("blocked connection remained open")
                try: extra,_=blocked_target.accept()
                except TimeoutError: pass
                else: extra.close(); raise RuntimeError("blocked connection reached target")
            concurrent_transfer(socks_port)
            with connect_proxy(socks_port,target.getsockname()[1]) as active:
                active.sendall(b"ready")
                with target.accept()[0] as upstream:
                    upstream.settimeout(5); active.settimeout(5)
                    if exact(upstream,5)!=b"ready": raise RuntimeError("active session not ready")
                    proxy.terminate(); proxy.wait(timeout=5)
                    if upstream.recv(1)!=b"": raise RuntimeError("upstream remained open after stop")
                    try: closed=active.recv(1)
                    except ConnectionResetError: closed=b""
                    if closed!=b"": raise RuntimeError("client remained open after stop")
    finally:
        if box is not None:
            box.terminate()
            try: box.communicate(timeout=5)
            except subprocess.TimeoutExpired: box.kill(); box.communicate()
        proxy.terminate()
        try: out,err=proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired: proxy.kill(); out,err=proxy.communicate()
        if proxy.returncode!=0: raise RuntimeError(f"proxy exit {proxy.returncode}: {err}")
with tempfile.TemporaryDirectory(prefix="nexus-ss-inbound-") as directory:
    for size in (16,32):
        for workers in (1,2): scenario(pathlib.Path(directory),size,workers)
print(f"SS-2022 KDL inbound with sing-box {revision} passed")
