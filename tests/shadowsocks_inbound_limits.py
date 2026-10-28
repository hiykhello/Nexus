#!/usr/bin/env python3
"""Check SS-2022 session quota sharing and recovery on the real CLI."""
import base64
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
wire_tool=nexus.with_name("nexus-shadowsocks-replay-wire")

def closed(sock):
    try: return sock.recv(1)==b""
    except ConnectionResetError: return True

def scenario(root,size,workers):
    with socket.socket() as target, socket.socket() as reserved:
        target.bind(("127.0.0.1",0)); target.listen(128); target.settimeout(5)
        reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]; reserved.close()
        key=root/"key"; key.write_text(base64.b64encode(bytes(range(size))).decode()+"\n"); key.chmod(0o600)
        config=root/"server.kdl"; config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{ shadowsocks "ss" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }} }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
        proxy=subprocess.Popen([nexus,"run","--config",config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        clients=[]; upstreams=[]
        try:
            deadline=time.monotonic()+5
            while True:
                if proxy.poll() is not None: raise RuntimeError(proxy.stderr.read().decode())
                try: ready=socket.create_connection(("127.0.0.1",port),timeout=.2); ready.close(); break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            def request(offset):
                return subprocess.run([wire_tool,str(size),str(target.getsockname()[1]),str(offset)],check=True,capture_output=True).stdout
            for offset in range(64):
                client=socket.create_connection(("127.0.0.1",port),timeout=5); client.settimeout(5)
                clients.append(client); client.sendall(request(offset))
                upstream,_=target.accept(); upstream.settimeout(5); upstreams.append(upstream)
            # All leases are held by established sessions before probing the limit.
            with socket.create_connection(("127.0.0.1",port),timeout=5) as extra:
                extra.settimeout(5)
                try: extra.sendall(request(100))
                except (ConnectionResetError,BrokenPipeError): pass
                if not closed(extra): raise RuntimeError("65th session was not rejected")
            target.settimeout(.2)
            try: extra,_=target.accept()
            except TimeoutError: pass
            else: extra.close(); raise RuntimeError("65th session reached target")
            # Closing one end drains both relay directions and releases its lease.
            clients[0].close()
            if not closed(upstreams[0]): raise RuntimeError("closed client did not close upstream")
            upstreams[0].close()
            target.settimeout(2)
            deadline=time.monotonic()+5
            for offset in range(110,150):
                replacement=socket.create_connection(("127.0.0.1",port),timeout=2); replacement.settimeout(2)
                try:
                    replacement.sendall(request(offset))
                    try: upstream,_=target.accept()
                    except TimeoutError:
                        replacement.close()
                        if time.monotonic()>=deadline: raise RuntimeError("session quota was not reclaimed")
                        continue
                    upstream.settimeout(5)
                    clients.append(replacement); upstreams.append(upstream)
                    break
                except (ConnectionResetError,BrokenPipeError):
                    replacement.close()
                    if time.monotonic()>=deadline: raise RuntimeError("session quota was not reclaimed")
            else: raise RuntimeError("session quota was not reclaimed")
            proxy.terminate(); proxy.wait(timeout=5)
            for sock in clients[1:]+upstreams[1:]:
                if not closed(sock): raise RuntimeError("session remained open after shutdown")
        finally:
            for sock in clients+upstreams: sock.close()
            if proxy.poll() is None: proxy.terminate()
            try: _,err=proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired: proxy.kill(); _,err=proxy.communicate()
            if proxy.returncode!=0: raise RuntimeError(f"nexus exit {proxy.returncode}: {err.decode()}")

with tempfile.TemporaryDirectory(prefix="nexus-ss-limits-") as directory:
    for size,workers in ((16,1),(32,2)): scenario(pathlib.Path(directory),size,workers)
print("SS-2022 inbound quota, recovery and shutdown passed")
