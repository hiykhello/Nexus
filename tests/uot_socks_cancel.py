#!/usr/bin/env python3
"""SOCKS UoT sessions cancel stalled SS peers on control close and stop."""
import base64
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
def exact(sock,n):
    out=b""
    while len(out)<n:
        data=sock.recv(n-len(out))
        if not data: raise RuntimeError("unexpected EOF")
        out+=data
    return out
with tempfile.TemporaryDirectory(prefix="nexus-uot-cancel-") as directory, socket.socket() as upstream:
    root=pathlib.Path(directory); key=base64.b64encode(bytes(range(16))).decode(); (root/"key").write_text(key); (root/"key").chmod(0o600)
    upstream.bind(("127.0.0.1",0)); upstream.listen(8); upstream.settimeout(5)
    with socket.socket() as reserved: reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]
    (root/"config.kdl").write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={upstream.getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
routing {{ final "edge"; }}
''')
    proxy=subprocess.Popen([nexus,"run","--config",root/"config.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        deadline=time.monotonic()+10
        while True:
            if proxy.poll() is not None: raise RuntimeError(f"proxy exited: {proxy.stderr.read()!r}")
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.2): break
            except OSError:
                if time.monotonic()>deadline: raise
                time.sleep(.05)
        def start():
            control=socket.create_connection(("127.0.0.1",port),timeout=5); control.settimeout(5)
            client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); client.bind(("127.0.0.1",0))
            control.sendall(b"\x05\x01\x00"); assert exact(control,2)==b"\x05\x00"
            control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"); reply=exact(control,10)
            if reply[:4]!=b"\x05\x00\x00\x01": raise RuntimeError(f"association: {reply!r}")
            relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],"big"))
            client.sendto(b"\x00\x00\x00\x01\x7f\x00\x00\x01\x00\x35probe",relay)
            remote,_=upstream.accept(); remote.settimeout(5)
            if not remote.recv(4096): raise RuntimeError("no encrypted request")
            return control,client,remote
        def wait_closed(remote):
            total=0
            while True:
                data=remote.recv(65536)
                if not data: return
                total+=len(data)
                if total>131072: raise RuntimeError("unexpected upstream traffic")
        for _ in range(70):
            control,client,remote=start(); control.close(); client.close(); wait_closed(remote); remote.close()
        control,client,remote=start()
        proxy.terminate(); _,stderr=proxy.communicate(timeout=10)
        if proxy.returncode: raise RuntimeError(f"shutdown: {proxy.returncode} {stderr!r}")
        wait_closed(remote); remote.close(); control.close(); client.close()
        print("UoT stalled upstream cancellation, quota recovery and active shutdown passed")
    finally:
        if proxy.poll() is None: proxy.terminate(); proxy.communicate(timeout=5)
