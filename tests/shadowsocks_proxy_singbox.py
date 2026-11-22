#!/usr/bin/env python3
"""Exercise a Nexus proxy server using the experimental SS-2022 outbound API."""
import base64
import json
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")

def exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size-len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        data += chunk
    return data

def scenario(root, size, workers, legacy):
    with socket.socket() as target, socket.socket() as reserved:
        target.bind(("127.0.0.1",0)); target.listen(1); target.settimeout(5)
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
            args=[fixture,"0",str(upstream_port),str(size),str(workers)]
            if legacy: args.append("legacy")
            proxy=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            if not select.select([proxy.stdout],[],[],5)[0]: raise RuntimeError("proxy failed to start")
            port=int(proxy.stdout.readline().strip())
            with socket.create_connection(("127.0.0.1",port),timeout=5) as client:
                client.settimeout(5); client.sendall(b"\x05\x01\x00")
                if exact(client,2)!=b"\x05\x00": raise RuntimeError("greeting failed")
                dest=target.getsockname()[1]
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+dest.to_bytes(2,"big"))
                head=exact(client,4)
                if head[1]!=0: raise RuntimeError(f"CONNECT failed: {head!r}")
                exact(client,6 if head[3]==1 else 18)
                client.sendall(b"helloagain"); client.shutdown(socket.SHUT_WR)
                with target.accept()[0] as upstream:
                    upstream.settimeout(5)
                    if exact(upstream,10)!=b"helloagain" or upstream.recv(1)!=b"": raise RuntimeError("upload failed")
                    upstream.sendall(b"worldagain"); upstream.shutdown(socket.SHUT_WR)
                    if exact(client,10)!=b"worldagain" or client.recv(1)!=b"": raise RuntimeError("download failed")
        finally:
            if proxy is not None:
                proxy.terminate()
                try: out,err=proxy.communicate(timeout=5)
                except subprocess.TimeoutExpired: proxy.kill(); out,err=proxy.communicate()
                if proxy.returncode!=0: raise RuntimeError(f"proxy exit {proxy.returncode}: {err}")
            box.terminate()
            try: box.communicate(timeout=5)
            except subprocess.TimeoutExpired: box.kill(); box.communicate()

with tempfile.TemporaryDirectory(prefix="nexus-ss2022-proxy-") as directory:
    # Exercise the two relay directions under several startup interleavings.
    for _ in range(4):
        for size in (16,32):
            for workers in (1,2):
                for legacy in (False,True): scenario(pathlib.Path(directory),size,workers,legacy)
print(f"SS-2022 Nexus proxy API with sing-box {revision} passed")
