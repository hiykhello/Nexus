#!/usr/bin/env python3
"""Test a real SS-2022 client FIN against both Nexus and sing-box servers."""
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
client=nexus.with_name("nexus-shadowsocks-singbox-client")
revision="824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box","version"],check=True,capture_output=True,text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")

def exact(sock,size):
    data=bytearray()
    while len(data)<size:
        chunk=sock.recv(size-len(data))
        if not chunk: raise RuntimeError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)

def scenario(root,size,server,empty):
    with socket.socket() as target, socket.socket() as reserved:
        target.bind(("127.0.0.1",0)); target.listen(1); target.settimeout(10)
        reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]; reserved.close()
        method=f"2022-blake3-aes-{size*8}-gcm"
        password=base64.b64encode(bytes(range(size))).decode()
        if server=="nexus":
            key=root/"key"; key.write_text(password+"\n"); key.chmod(0o600)
            conf=root/"server.kdl"; conf.write_text(f'''schema-version 1
role "server"
inbounds {{ shadowsocks "ss" {{ listen host="127.0.0.1" port={port}; method "{method}"; key-file "{key}"; }} }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
            command=[nexus,"run","--config",conf]
        else:
            conf=root/"server.json"; conf.write_text(json.dumps({"log":{"level":"warn"},
                "inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":port,"method":method,"password":password}],
                "outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}))
            command=["sing-box","run","-c",conf]
        proxy=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        peer=None
        try:
            deadline=time.monotonic()+5
            while True:
                if proxy.poll() is not None: raise RuntimeError(proxy.stderr.read().decode())
                try: connection=socket.create_connection(("127.0.0.1",port),timeout=.2); break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            with connection:
                connection.setblocking(True)
                peer=subprocess.Popen([client,str(connection.fileno()),str(size),str(target.getsockname()[1]),"half-close-empty" if empty else "half-close"],
                                      pass_fds=(connection.fileno(),))
                with target.accept()[0] as upstream:
                    upstream.settimeout(10)
                    if exact(upstream,10)!=b"helloagain": raise RuntimeError("upload mismatch")
                    if upstream.recv(1)!=b"": raise RuntimeError("target did not receive FIN")
                    if not empty: upstream.sendall(b"worldagain")
                    upstream.shutdown(socket.SHUT_WR)
                if peer.wait(timeout=10)!=0: raise RuntimeError(f"client failed: {peer.returncode}")
        finally:
            if peer is not None and peer.poll() is None: peer.kill(); peer.wait()
            proxy.terminate()
            try: _,err=proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired: proxy.kill(); _,err=proxy.communicate()
            if proxy.returncode!=0 and server=="nexus": raise RuntimeError(f"nexus failed: {err.decode()}")

with tempfile.TemporaryDirectory(prefix="nexus-ss-half-close-") as directory:
    for server in ("nexus","sing-box"):
        for size in (16,32):
            for empty in (False,True): scenario(pathlib.Path(directory),size,server,empty)
print("SS-2022 TCP client half-close against Nexus and sing-box passed")
