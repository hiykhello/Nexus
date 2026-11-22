#!/usr/bin/env python3
"""Authenticated UoT spoofed replies and malformed/corrupt stream failures."""
import base64
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

nexus=pathlib.Path(sys.argv[1]).resolve(); fixture=nexus.with_name("nexus-uot-fault-server")
def exact(sock,n):
    out=b""
    while len(out)<n:
        data=sock.recv(n-len(out))
        if not data: raise RuntimeError("unexpected EOF")
        out+=data
    return out
with tempfile.TemporaryDirectory(prefix="nexus-uot-fault-") as directory:
    root=pathlib.Path(directory); key=base64.b64encode(bytes(range(16))).decode(); (root/"key").write_text(key); (root/"key").chmod(0o600)
    for mode in ("valid","invalid","corrupt","truncated"):
        with socket.socket() as upstream, socket.socket() as reserved:
            upstream.bind(("127.0.0.1",0)); upstream.listen(1); reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]; reserved.close()
            (root/"config.kdl").write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={upstream.getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
routing {{ default-outbound "edge"; }}
''')
            read_fd,write_fd=os.pipe(); peer=proxy=None
            try:
                peer=subprocess.Popen([fixture,str(upstream.fileno()),mode,str(read_fd)],pass_fds=(upstream.fileno(),read_fd)); os.close(read_fd); read_fd=-1
                proxy=subprocess.Popen([nexus,"run","--config",root/"config.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                deadline=time.monotonic()+5
                while True:
                    if proxy.poll() is not None: raise RuntimeError(f"proxy exited: {proxy.stderr.read()!r}")
                    try: control=socket.create_connection(("127.0.0.1",port),timeout=.2); break
                    except OSError:
                        if time.monotonic()>deadline: raise
                        time.sleep(.02)
                with control, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                    control.settimeout(5); client.settimeout(5); client.bind(("127.0.0.1",0))
                    control.sendall(b"\x05\x01\x00"); assert exact(control,2)==b"\x05\x00"
                    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"); reply=exact(control,10)
                    if reply[:4]!=b"\x05\x00\x00\x01": raise RuntimeError(f"association: {reply!r}")
                    relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],"big"))
                    header=b"\x00\x00\x00\x01\x7f\x00\x00\x01\x00\x35"
                    client.sendto(header+b"probe",relay)
                    got,_=client.recvfrom(65535)
                    if got!=header+b"good": raise RuntimeError(f"forged or wrong first reply: {got!r}")
                    client.settimeout(.2)
                    try: raise RuntimeError(f"unexpected extra reply: {client.recvfrom(65535)!r}")
                    except socket.timeout: pass
                    os.write(write_fd,b"x"); os.close(write_fd); write_fd=-1
                    if peer.wait(timeout=5): raise RuntimeError(f"fixture exit {peer.returncode}")
                    control.settimeout(5)
                    try: closed=control.recv(1)
                    except ConnectionResetError: closed=b""
                    if closed: raise RuntimeError(f"control not closed on {mode}")
                    client.settimeout(.2)
                    try: raise RuntimeError(f"unexpected post-fault reply: {client.recvfrom(65535)!r}")
                    except socket.timeout: pass
                if proxy.poll() is not None: raise RuntimeError("proxy exited after session failure")
                proxy.terminate(); _,stderr=proxy.communicate(timeout=5)
                if proxy.returncode: raise RuntimeError(f"proxy shutdown: {stderr!r}")
                proxy=None
            finally:
                if read_fd>=0: os.close(read_fd)
                if write_fd>=0: os.close(write_fd)
                if peer and peer.poll() is None: peer.kill(); peer.wait()
                if proxy and proxy.poll() is None: proxy.terminate(); proxy.communicate(timeout=5)
print("UoT spoofed source rejected; malformed, corrupt and truncated responses close session")
