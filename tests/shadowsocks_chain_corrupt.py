#!/usr/bin/env python3
"""Reject unauthenticated response frames after a valid SS-2022 chain response."""
import base64
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
fixture=nexus.with_name("nexus-shadowsocks-singbox-fixture")
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

def start(command,port):
    process=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    deadline=time.monotonic()+5
    while True:
        if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
        try: check=socket.create_connection(("127.0.0.1",port),timeout=.2); check.close(); return process
        except OSError:
            if time.monotonic()>deadline: process.kill(); process.communicate(); raise
            time.sleep(.02)

def stop(process):
    if process is None: return
    process.terminate()
    try: _,err=process.communicate(timeout=5)
    except subprocess.TimeoutExpired: process.kill(); _,err=process.communicate()
    if process.returncode!=0: raise RuntimeError(f"process exit {process.returncode}: {err.decode()}")

def scenario(root,size,mode):
    with socket.socket() as listener, socket.socket() as reserved, socket.socket() as reserved2:
        listener.bind(("127.0.0.1",0)); listener.listen(8)
        reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]; reserved.close()
        reserved2.bind(("127.0.0.1",0)); socks_port=reserved2.getsockname()[1]; reserved2.close()
        key=root/"key"; key.write_text(base64.b64encode(bytes(range(size))).decode()+"\n"); key.chmod(0o600)
        config=root/"nexus.kdl"; config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ shadowsocks "input" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }} }}
outbounds {{ direct "direct"; shadowsocks "edge" {{ server host="127.0.0.1" port={listener.getsockname()[1]}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }} }}
routing {{ default-outbound "edge"; }}
''')
        config_box={"log":{"level":"warn"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":socks_port}],
            "outbounds":[{"type":"shadowsocks","tag":"edge","server":"127.0.0.1","server_port":port,
                "method":f"2022-blake3-aes-{size*8}-gcm","password":base64.b64encode(bytes(range(size))).decode()}],
            "route":{"final":"edge"}}
        box_config=root/"client.json"; box_config.write_text(json.dumps(config_box))
        read_fd,write_fd=os.pipe(); peer=None; proxy=None; box=None
        try:
            peer=subprocess.Popen([fixture,str(listener.fileno()),str(size),mode,str(read_fd)],pass_fds=(listener.fileno(),read_fd))
            os.close(read_fd); read_fd=-1
            proxy=start([nexus,"run","--config",config],port)
            box=start(["sing-box","run","-c",box_config],socks_port)
            with socket.create_connection(("127.0.0.1",socks_port),timeout=5) as client:
                client.settimeout(5); client.sendall(b"\x05\x01\x00")
                if exact(client,2)!=b"\x05\x00": raise RuntimeError("greeting failed")
                client.sendall(b"\x05\x01\x00\x01\xcb\x00\x71\x05\x01\xbb")
                head=exact(client,4)
                if head[1]: raise RuntimeError("SOCKS connect failed")
                exact(client,6 if head[3]==1 else 18)
                client.sendall(b"hello")
                try: first=exact(client,10)
                except (TimeoutError,RuntimeError) as exc: raise RuntimeError(f"authenticated response missing; fixture status {peer.poll()}") from exc
                if first!=b"worldagain": raise RuntimeError("authenticated response mismatch")
                os.write(write_fd,b"x"); os.close(write_fd); write_fd=-1
                try: rest=client.recv(1)
                except ConnectionResetError: rest=b""
                if rest: raise RuntimeError(f"unauthenticated bytes delivered: {rest!r}")
            if peer.wait(timeout=5)!=0: raise RuntimeError(f"fixture exit {peer.returncode}")
            listener.settimeout(.2)
            try: extra,_=listener.accept()
            except TimeoutError: pass
            else: extra.close(); raise RuntimeError("corrupt frame triggered upstream retry")
        finally:
            if read_fd>=0: os.close(read_fd)
            if write_fd>=0: os.close(write_fd)
            if peer is not None and peer.poll() is None: peer.kill(); peer.wait()
            stop(box); stop(proxy)

with tempfile.TemporaryDirectory(prefix="nexus-ss-corrupt-") as directory:
    for size in (16,32):
        for mode in ("length","payload","truncated"): scenario(pathlib.Path(directory),size,mode)
print("SS-2022 chained authenticated response and corrupt frame tests passed")
