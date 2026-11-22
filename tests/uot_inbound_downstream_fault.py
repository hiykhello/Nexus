#!/usr/bin/env python3
"""Reject invalid UoT and corrupt or truncated SS records from a downstream."""
import base64
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
fault=nexus.with_name("nexus-uot-fault-server"); client=nexus.with_name("nexus-proxy-uot-fixture")
with tempfile.TemporaryDirectory(prefix="nexus-uot-downstream-fault-") as directory:
    root=pathlib.Path(directory); (root/"key").write_text(base64.b64encode(bytes(range(16))).decode()); (root/"key").chmod(0o600)
    with socket.socket() as upstream:
        upstream.bind(("127.0.0.1",0)); upstream.listen(5)
        with socket.socket() as reserved: reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]
        (root/"config.kdl").write_text(f'''schema-version 1
role "server"
workers 2
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={upstream.getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
routing {{ default-outbound "edge"; }}
''')
        server=subprocess.Popen([nexus,"run","--config",root/"config.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+5
            while True:
                if server.poll() is not None: raise RuntimeError(f"server exited: {server.stderr.read()!r}")
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.2): break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            for mode in ("invalid","corrupt","truncated","valid"):
                read_fd,write_fd=os.pipe(); peer=client_process=None
                try:
                    peer=subprocess.Popen([fault,str(upstream.fileno()),mode,str(read_fd)],pass_fds=(upstream.fileno(),read_fd))
                    os.close(read_fd); read_fd=-1
                    client_process=subprocess.Popen([client,str(port),"53","0","downstream"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    if not select.select([client_process.stdout],[],[],5)[0] or client_process.stdout.readline()!=b"ready\n":
                        raise RuntimeError(f"{mode}: no initial valid reply")
                    os.write(write_fd,b"x"); os.close(write_fd); write_fd=-1
                    _,stderr=client_process.communicate(timeout=5)
                    if client_process.returncode: raise RuntimeError(f"{mode}: client {client_process.returncode} {stderr!r}")
                    if peer.wait(timeout=5): raise RuntimeError(f"{mode}: peer {peer.returncode}")
                    if server.poll() is not None: raise RuntimeError(f"server exited after {mode}")
                finally:
                    for fd in (read_fd,write_fd):
                        if fd>=0: os.close(fd)
                    for process in (peer,client_process):
                        if process and process.poll() is None: process.kill(); process.communicate(timeout=5)
            server.terminate(); _,stderr=server.communicate(timeout=5)
            if server.returncode: raise RuntimeError(f"shutdown: {stderr!r}")
            server=None
            print("UoT inbound downstream invalid, corrupt and truncated streams close; subsequent sessions recover")
        finally:
            if server and server.poll() is None: server.terminate(); server.communicate(timeout=5)
