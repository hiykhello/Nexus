#!/usr/bin/env python3
"""Exercise the SS-2022 Server API with an independent sing-box client."""
import base64
import json
import pathlib
import select
import signal
import socket
import subprocess
import sys
import tempfile
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
def scenario(root,size,workers):
    proxy=subprocess.Popen([fixture,str(size),str(workers)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    box=None
    try:
        if not select.select([proxy.stdout],[],[],5)[0]: raise RuntimeError("proxy did not start")
        port,second_port=map(int,proxy.stdout.readline().split())
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
            proxy.send_signal(signal.SIGUSR1)
            if not select.select([proxy.stdout],[],[],5)[0] or proxy.stdout.readline().strip()!="restarted":
                raise RuntimeError("proxy restart failed")
            with socket.create_connection(("127.0.0.1",port),timeout=5) as duplicate:
                duplicate.settimeout(5); duplicate.sendall(wire)
                try: result=duplicate.recv(1)
                except ConnectionResetError: pass
                else: raise RuntimeError(f"replay after restart did not reset: {result!r}")
            target.settimeout(.1)
            try: extra,_=target.accept()
            except TimeoutError: pass
            else: extra.close(); raise RuntimeError("replay after restart reached target")
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
print(f"SS-2022 Server API inbound with sing-box {revision} passed")
