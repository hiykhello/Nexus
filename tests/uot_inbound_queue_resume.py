#!/usr/bin/env python3
"""Resume a saturated UoT inbound queue after a delayed DNS answer."""
import base64
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

server_binary=pathlib.Path(sys.argv[1]).resolve(); fixture=server_binary.with_name("nexus-proxy-uot-fixture")
large=len(sys.argv)>2 and sys.argv[2]=="--large"
cancel="--cancel" in sys.argv[2:]
with tempfile.TemporaryDirectory(prefix="nexus-uot-queue-") as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as origin:
    root=pathlib.Path(directory); dns.bind(("127.0.0.1",0)); dns.settimeout(5)
    # The byte-limit case releases twenty 60 KiB datagrams together. Give the
    # test origin room for the burst so kernel queue loss does not masquerade
    # as a proxy queue failure.
    if large: origin.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)
    origin.bind(("127.0.0.2",0)); origin.settimeout(.1)
    with socket.socket() as reserve: reserve.bind(("127.0.0.1",0)); port=reserve.getsockname()[1]
    (root/"key").write_text(base64.b64encode(bytes(range(16))).decode()); (root/"key").chmod(0o600)
    (root/"server.kdl").write_text(f'''schema-version 1
role "server"
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}
inbounds {{ shadowsocks "ss" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }} }}
outbounds {{ direct "direct"; }}
routing {{ final "direct"; }}
''')
    stopped=threading.Event(); received=[]; errors=[]
    def echo():
        try:
            buffered=[]
            while not stopped.is_set():
                try: data,peer=origin.recvfrom(65535)
                except socket.timeout: continue
                received.append(data)
                if large:
                    buffered.append((data,peer))
                    if len(buffered)==20:
                        for payload,destination in buffered:
                            origin.sendto(payload,destination); time.sleep(.01)
                else: origin.sendto(data,peer)
        except Exception as exc: errors.append(exc)
    thread=threading.Thread(target=echo,daemon=True); thread.start()
    server=client=None
    try:
        server=subprocess.Popen([server_binary,"run","--config",root/"server.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=dict(os.environ,NEXUS_TEST_UOT_QUEUE_TRACE="1"))
        deadline=time.monotonic()+5
        while True:
            if server.poll() is not None: raise RuntimeError(f"server exited: {server.stderr.read()!r}")
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.2): break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        client=subprocess.Popen([fixture,str(port),str(origin.getsockname()[1]),"0","large" if large else "flood"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        query,peer=dns.recvfrom(512)
        if query[12:-4]!=b"\x07blocked\x04test\x00": raise RuntimeError("unexpected DNS name")
        if not select.select([client.stdout],[],[],5)[0] or client.stdout.readline()!=b"sent\n": raise RuntimeError("flood not sent")
        if not select.select([server.stderr],[],[],5)[0]: raise RuntimeError("queue did not reach capacity")
        trace=server.stderr.readline().split()
        if len(trace)!=6 or trace[:3]!=[b"uot",b"queue",b"full"]: raise RuntimeError(f"unexpected queue trace: {trace!r}")
        count,queued,waiting=map(int,trace[3:])
        if (large and (count>=64 or queued>1024*1024 or queued+waiting<=1024*1024)) or (not large and count!=64):
            raise RuntimeError(f"wrong queue limit: {trace!r}")
        if cancel:
            client.terminate(); client.communicate(timeout=5); client=None
            server.terminate(); _,stderr=server.communicate(timeout=5)
            if server.returncode: raise RuntimeError(f"shutdown: {stderr!r}")
            server=None
            print("UoT inbound byte-limited queue cancels while DNS is pending")
            sys.exit(0)
        reply=bytearray(query); reply[2:4]=b"\x81\x80"; reply[7]=1
        reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x02")
        dns.sendto(reply,peer)
        _,stderr=client.communicate(timeout=15)
        if client.returncode: raise RuntimeError(f"fixture failed: {client.returncode} {stderr!r}; received {len(received)}")
        client=None
        expected=[bytes([i])*60000 for i in range(20)] if large else [b"uot-probe"]*100
        if received!=expected or errors: raise RuntimeError(f"origin received {len(received)} packets; errors={errors!r}")
        server.terminate(); _,stderr=server.communicate(timeout=5)
        if server.returncode: raise RuntimeError(f"shutdown: {stderr!r}")
        server=None
        print(f"UoT inbound {'byte' if large else 'count'}-limited queue resumes and delivers all datagrams after DNS")
    finally:
        stopped.set(); thread.join(timeout=1)
        if client and client.poll() is None: client.kill(); client.communicate(timeout=5)
        if server and server.poll() is None: server.terminate(); server.communicate(timeout=5)
