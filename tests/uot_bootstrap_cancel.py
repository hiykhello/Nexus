#!/usr/bin/env python3
"""Cancel pending UoT bootstrap lookups on SOCKS closure and server stop."""
import base64
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
def exact(sock,n):
    out=b""
    while len(out)<n:
        part=sock.recv(n-len(out))
        if not part: raise RuntimeError("unexpected EOF")
        out+=part
    return out
with tempfile.TemporaryDirectory(prefix="nexus-uot-bootstrap-cancel-") as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
    root=pathlib.Path(directory); (root/"key").write_text(base64.b64encode(bytes(range(16))).decode()); (root/"key").chmod(0o600)
    dns.bind(("127.0.0.1",0)); dns.settimeout(3)
    with socket.socket() as reserved: reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]
    (root/"config.kdl").write_text(f'''schema-version 1
role "client"
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; }}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{ server host="edge.test" port=8443; bootstrap-resolver "dns"; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
routing {{ final "edge"; }}
''')
    proxy=subprocess.Popen([nexus,"run","--config",root/"config.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        deadline=time.monotonic()+5
        while True:
            if proxy.poll() is not None: raise RuntimeError(f"proxy exited: {proxy.stderr.read()!r}")
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.2): break
            except OSError:
                if time.monotonic()>deadline: raise
                time.sleep(.02)
        def begin():
            control=socket.create_connection(("127.0.0.1",port),timeout=3); control.settimeout(3)
            udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind(("127.0.0.1",0))
            control.sendall(b"\x05\x01\x00"); assert exact(control,2)==b"\x05\x00"
            control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"); reply=exact(control,10)
            relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],"big"))
            udp.sendto(b"\x00\x00\x00\x01\x7f\x00\x00\x01\x00\x35probe",relay)
            query,_=dns.recvfrom(512)
            if query[12:-4].lower()!=b"\x04edge\x04test\x00": raise RuntimeError(f"wrong lookup: {query!r}")
            return control,udp
        for _ in range(70):
            control,udp=begin(); control.close(); udp.close()
        control,udp=begin(); proxy.terminate(); _,stderr=proxy.communicate(timeout=10)
        if proxy.returncode: raise RuntimeError(f"shutdown: {proxy.returncode} {stderr!r}")
        control.close(); udp.close()
        print("UoT stalled bootstrap cancellation, quota recovery and active shutdown passed")
    finally:
        if proxy.poll() is None: proxy.terminate(); proxy.communicate(timeout=5)
