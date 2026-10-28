#!/usr/bin/env python3
"""Reject corrupted post-handshake client frames at the SS-2022 inbound."""
import base64
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
client=nexus.with_name("nexus-shadowsocks-singbox-client")

def exact(sock,size):
    data=bytearray()
    while len(data)<size:
        part=sock.recv(size-len(data))
        if not part: raise RuntimeError("unexpected EOF")
        data.extend(part)
    return bytes(data)

def scenario(root,size,mode):
    with socket.socket() as target, socket.socket() as reserved:
        target.bind(("127.0.0.1",0)); target.listen(2); target.settimeout(5)
        reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]; reserved.close()
        key=root/"key"; key.write_text(base64.b64encode(bytes(range(size))).decode()+"\n"); key.chmod(0o600)
        config=root/"server.kdl"; config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ shadowsocks "ss" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }} }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
        proxy=subprocess.Popen([nexus,"run","--config",config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        read_fd,write_fd=os.pipe(); peer=None
        try:
            deadline=time.monotonic()+5
            while True:
                if proxy.poll() is not None: raise RuntimeError(proxy.stderr.read().decode())
                try: connection=socket.create_connection(("127.0.0.1",port),timeout=.2); break
                except OSError:
                    if time.monotonic()>deadline: raise
                    time.sleep(.02)
            with connection:
                connection.setblocking(True)
                peer=subprocess.Popen([client,str(connection.fileno()),str(size),str(target.getsockname()[1]),mode,str(read_fd)],
                                      pass_fds=(connection.fileno(),read_fd))
                os.close(read_fd); read_fd=-1
                with target.accept()[0] as upstream:
                    upstream.settimeout(5)
                    if exact(upstream,10)!=b"helloagain": raise RuntimeError("authenticated request missing")
                    os.write(write_fd,b"x"); os.close(write_fd); write_fd=-1
                    try: rest=upstream.recv(1)
                    except ConnectionResetError: rest=b""
                    if rest: raise RuntimeError(f"unauthenticated bytes delivered: {rest!r}")
                if peer.wait(timeout=5)!=0: raise RuntimeError(f"client exit {peer.returncode}")
            target.settimeout(.2)
            try: extra,_=target.accept()
            except TimeoutError: pass
            else: extra.close(); raise RuntimeError("corrupt frame triggered target retry")
        finally:
            if read_fd>=0: os.close(read_fd)
            if write_fd>=0: os.close(write_fd)
            if peer is not None and peer.poll() is None: peer.kill(); peer.wait()
            proxy.terminate()
            try: _,err=proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired: proxy.kill(); _,err=proxy.communicate()
            if proxy.returncode!=0: raise RuntimeError(f"nexus exit {proxy.returncode}: {err.decode()}")

with tempfile.TemporaryDirectory(prefix="nexus-ss-in-corrupt-") as directory:
    for size in (16,32):
        for mode in ("length","payload","truncated"): scenario(pathlib.Path(directory),size,mode)
print("SS-2022 inbound authenticated request and corrupt frame tests passed")
