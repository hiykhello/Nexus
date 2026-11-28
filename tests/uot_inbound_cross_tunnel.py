#!/usr/bin/env python3
"""Check reply authorization isolation across UoT inbound outbound streams."""
import base64
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
fault=nexus.with_name("nexus-uot-fault-server"); client=nexus.with_name("nexus-proxy-uot-fixture")
for reverse in (False,True):
    with tempfile.TemporaryDirectory(prefix="nexus-uot-inbound-cross-") as directory:
        root=pathlib.Path(directory); (root/"key").write_text(base64.b64encode(bytes(range(16))).decode()); (root/"key").chmod(0o600)
        (root/"second.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
        listeners=[]; peers=[]; pipes=[]; server=None
        try:
            for _ in range(2):
                listener=socket.socket(); listener.bind(("127.0.0.1",0)); listener.listen(1); listeners.append(listener)
                read_fd,write_fd=os.pipe(); pipes.append(write_fd)
                peers.append(subprocess.Popen([fault,str(listener.fileno()),"valid",str(read_fd)],pass_fds=(listener.fileno(),read_fd)))
                os.close(read_fd)
            with socket.socket() as reserve: reserve.bind(("127.0.0.1",0)); port=reserve.getsockname()[1]
            (root/"server.kdl").write_text(f'''schema-version 1
role "server"
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }}
outbound "direct" type="direct"
outbound "first" type="shadowsocks" {{ server host="127.0.0.1" port={listeners[0].getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
outbound "second" type="shadowsocks" {{ server host="127.0.0.1" port={listeners[1].getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
routing {{ rulesets {{ "second" path="second.kdl" format="kdl"; }}; rules {{ - rule-set="second" to="second"; }}; final "first"; }}
''')
            server=subprocess.Popen([nexus,"run","--config",root/"server.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            deadline=time.monotonic()+5
            while True:
                if server.poll() is not None: raise RuntimeError(f"server exited: {server.stderr.read()!r}")
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.2): break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            result=subprocess.run([client,str(port),"53","1" if reverse else "0","cross"],capture_output=True,timeout=20)
            if result.returncode: raise RuntimeError(f"cross probe failed: {result.returncode} {result.stderr!r}")
            for fd in pipes: os.write(fd,b"x")
            for peer in peers:
                if peer.wait(timeout=5): raise RuntimeError(f"fault peer exit {peer.returncode}")
            server.terminate(); _,stderr=server.communicate(timeout=5)
            if server.returncode: raise RuntimeError(f"shutdown: {stderr!r}")
            server=None
        finally:
            for fd in pipes: os.close(fd)
            for peer in peers:
                if peer.poll() is None: peer.kill(); peer.wait()
            if server and server.poll() is None: server.terminate(); server.communicate(timeout=5)
            for listener in listeners: listener.close()
print("UoT inbound cross-outbound forged replies rejected in both authorization orders")
