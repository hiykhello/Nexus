#!/usr/bin/env python3
"""Cancel pending UoT inbound DNS and verify session quota recovery."""
import base64
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

nexus=pathlib.Path(sys.argv[1]).resolve(); fixture=nexus.with_name("nexus-proxy-uot-fixture")
flood="--flood" in sys.argv[2:]
bootstrap="--bootstrap" in sys.argv[2:]
with tempfile.TemporaryDirectory(prefix="nexus-uot-inbound-cancel-") as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
    root=pathlib.Path(directory); dns.bind(("127.0.0.1",0)); dns.settimeout(5)
    with socket.socket() as reserve: reserve.bind(("127.0.0.1",0)); port=reserve.getsockname()[1]
    (root/"key").write_text(base64.b64encode(bytes(range(16))).decode()); (root/"key").chmod(0o600)
    edge=(f'outbound "edge" type="shadowsocks" {{ server host="edge.test" port=8443; bootstrap-resolver "dns"; method "2022-blake3-aes-128-gcm"; key-file "{root/"key"}"; udp-over-tcp "v2"; }}' if bootstrap else '')
    (root/"server.kdl").write_text(f'''schema-version 1
role "server"
workers 2
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; disable-cache #true; }}
inbounds {{ shadowsocks "ss" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }} }}
outbound "direct" type="direct"
{edge}
routing {{ default-outbound "{'edge' if bootstrap else 'direct'}"; }}
''')
    server=client=None
    try:
        env=dict(os.environ)
        if flood: env["NEXUS_TEST_UOT_QUEUE_TRACE"]="1"
        server=subprocess.Popen([nexus,"run","--config",root/"server.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=env)
        deadline=time.monotonic()+5
        while True:
            if server.poll() is not None: raise RuntimeError(f"server exited: {server.stderr.read()!r}")
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.2): break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        def start():
            global client
            args=[fixture,str(port),"5353","0"]
            if flood: args.append("numeric" if bootstrap else "flood")
            elif not bootstrap: args.append("policy")
            client=subprocess.Popen(args,stdout=subprocess.PIPE if flood else subprocess.DEVNULL,stderr=subprocess.PIPE)
            query,_=dns.recvfrom(512)
            expected=b"\x04edge\x04test\x00" if bootstrap else b"\x07blocked\x04test\x00"
            if query[12:-4]!=expected: raise RuntimeError(f"unexpected DNS query: {query!r}")
            if flood:
                if not select.select([client.stdout],[],[],5)[0] or client.stdout.readline()!=b"sent\n": raise RuntimeError("flood not sent")
                if not select.select([server.stderr],[],[],5)[0] or not server.stderr.readline().startswith(b"uot queue full 64 "): raise RuntimeError("queue did not reach capacity")
        for iteration in range(70):
            try: start()
            except socket.timeout as exc: raise RuntimeError(f"DNS query missing after {iteration} canceled sessions; quota may still be held") from exc
            client.terminate(); client.communicate(timeout=5); client=None
        start()
        server.terminate(); _,stderr=server.communicate(timeout=5)
        if server.returncode: raise RuntimeError(f"shutdown failed: {server.returncode} {stderr!r}")
        server=None
        client.communicate(timeout=5); client=None
        print(f"UoT inbound pending {'bootstrap ' if bootstrap else ''}DNS cancellation, {'flood, ' if flood else ''}quota recovery and active shutdown passed")
    finally:
        if client and client.poll() is None: client.kill(); client.communicate(timeout=5)
        if server and server.poll() is None: server.terminate(); server.communicate(timeout=5)
