#!/usr/bin/env python3
"""Authenticated malformed UoT streams terminate without forwarding data."""
import base64
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

nexus=pathlib.Path(sys.argv[1]).resolve(); fixture=nexus.with_name("nexus-proxy-uot-fixture")
with tempfile.TemporaryDirectory(prefix="nexus-uot-invalid-") as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as origin:
    root=pathlib.Path(directory); origin.bind(("127.0.0.1",0)); origin.settimeout(.2)
    with socket.socket() as reserved: reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]
    (root/"key").write_text(base64.b64encode(bytes(range(16))).decode()); (root/"key").chmod(0o600)
    (root/"config.kdl").write_text(f'''schema-version 1
role "server"
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
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
        for mode in range(3):
            result=subprocess.run([fixture,str(port),str(origin.getsockname()[1]),"0",f"i{mode}"],capture_output=True,timeout=20)
            if result.returncode: raise RuntimeError(f"invalid {mode}: {result.returncode} {result.stderr!r}")
            try: raise RuntimeError(f"invalid stream forwarded {origin.recvfrom(65535)!r}")
            except socket.timeout: pass
        def echo():
            data,peer=origin.recvfrom(65535); origin.sendto(data,peer)
        origin.settimeout(5); worker=threading.Thread(target=echo); worker.start()
        result=subprocess.run([fixture,str(port),str(origin.getsockname()[1]),"0"],capture_output=True,timeout=20)
        worker.join(timeout=5)
        if result.returncode or worker.is_alive(): raise RuntimeError(f"recovery failed: {result.returncode} {result.stderr!r}")
        server.terminate(); _,stderr=server.communicate(timeout=5)
        if server.returncode: raise RuntimeError(f"shutdown: {stderr!r}")
        server=None
        print("UoT inbound rejects malformed request, invalid frame and truncated frame; subsequent session works")
    finally:
        if server and server.poll() is None: server.terminate(); server.communicate(timeout=5)
