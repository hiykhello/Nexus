#!/usr/bin/env python3
"""Hold a chained UoT write authorization open until a reply arrives."""
import base64
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

server_binary=pathlib.Path(sys.argv[1]).resolve()
client_binary=server_binary.with_name("nexus-proxy-uot-fixture")
fault_binary=server_binary.with_name("nexus-uot-fault-server")
for mode in ("success","failure","cancel"):
    with tempfile.TemporaryDirectory(prefix="nexus-uot-inbound-race-") as directory, socket.socket() as upstream:
        root=pathlib.Path(directory); (root/"key").write_text(base64.b64encode(bytes(range(16))).decode()); (root/"key").chmod(0o600)
        upstream.bind(("127.0.0.1",0)); upstream.listen(1)
        with socket.socket() as reserve: reserve.bind(("127.0.0.1",0)); port=reserve.getsockname()[1]
        (root/"server.kdl").write_text(f'''schema-version 1
role "server"
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={upstream.getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
routing {{ default-outbound "edge"; }}
''')
        peer_read,peer_write=os.pipe(); gate_read,gate_write=os.pipe(); peer=server=client=None
        try:
            peer=subprocess.Popen([fault_binary,str(upstream.fileno()),"valid",str(peer_read)],pass_fds=(upstream.fileno(),peer_read))
            server=subprocess.Popen([server_binary,"run","--config",root/"server.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
                                    env=dict(os.environ,NEXUS_TEST_UOT_INBOUND_RACE=str(gate_read)),pass_fds=(gate_read,))
            os.close(peer_read); peer_read=-1; os.close(gate_read); gate_read=-1
            deadline=time.monotonic()+5
            while True:
                if server.poll() is not None: raise RuntimeError(f"server exited: {server.stderr.read()!r}")
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.2): break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            client=subprocess.Popen([client_binary,str(port),"53","0","race"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            if not select.select([server.stderr],[],[],5)[0] or server.stderr.readline()!=b"uot inbound reply pending\n":
                raise RuntimeError("reply did not reach pending authorization")
            time.sleep(.1)
            if client.poll() is not None: raise RuntimeError("client completed before write authorization")
            if mode=="cancel":
                client.terminate(); client.communicate(timeout=5); client=None
            else:
                os.write(gate_write,b"s" if mode=="success" else b"f")
                _,stderr=client.communicate(timeout=5)
                if (client.returncode==0)!=(mode=="success"): raise RuntimeError(f"{mode}: client exit {client.returncode} {stderr!r}")
                client=None
            os.write(peer_write,b"x")
            if peer.wait(timeout=5): raise RuntimeError(f"fault peer exit {peer.returncode}")
            server.terminate(); _,stderr=server.communicate(timeout=5)
            if server.returncode: raise RuntimeError(f"server shutdown: {stderr!r}")
            server=None
        finally:
            for fd in (peer_read,peer_write,gate_read,gate_write):
                if fd>=0: os.close(fd)
            for process in (client,peer,server):
                if process and process.poll() is None: process.terminate(); process.communicate(timeout=5)
print("UoT inbound chained reply waits for write success and is dropped on failure or cancellation")
