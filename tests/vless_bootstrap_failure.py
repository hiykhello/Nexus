#!/usr/bin/env python3
"""Check VLESS bootstrap failure and shutdown while DNS is pending."""
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
guard = pathlib.Path(sys.argv[2]).resolve()

def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count-len(data))
        if not chunk: raise RuntimeError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)

with tempfile.TemporaryDirectory(prefix="nexus-vless-bootstrap-") as directory:
    root = pathlib.Path(directory)
    key, cert, uuid = (root / name for name in ("key", "cert", "uuid"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-subj", "/CN=localhost", "-days", "1"], capture_output=True, check=True, timeout=10)
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    for mode in ("failure", "stop"):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns, socket.socket() as reserved:
            dns.bind(("127.0.0.1", 0)); dns.settimeout(8)
            reserved.bind(("127.0.0.1", 0)); port=reserved.getsockname()[1]; reserved.close()
            config=root / "proxy.kdl"
            config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ bootstrap-resolver "boot"; server host="edge.test" port=443; authentication {{ uuid-file "{uuid}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}; }}
routing {{ default-outbound "edge"; }}
''')
            env=os.environ.copy(); env["LD_PRELOAD"]=str(guard)
            process=subprocess.Popen([binary,"run","--config",config],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+5
                while True:
                    if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
                    try: client=socket.create_connection(("127.0.0.1",port),timeout=.2); break
                    except OSError:
                        if time.monotonic()>=deadline: raise
                        time.sleep(.02)
                with client:
                    client.settimeout(5); client.sendall(b"\x05\x01\x00")
                    if exact(client,2)!=b"\x05\x00": raise RuntimeError("SOCKS negotiation failed")
                    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2")
                    query,source=dns.recvfrom(512)
                    if query[12:]!=b"\x04edge\x04test\x00\x00\x01\x00\x01": raise RuntimeError("wrong DNS query")
                    if mode=="failure":
                        response=bytearray(query); response[2:4]=b"\x81\x82"; dns.sendto(response,source)
                        reply=exact(client,10)
                        if reply[0]!=5 or reply[1]==0: raise RuntimeError("DNS failure reported success")
                    else:
                        process.terminate(); process.wait(timeout=5)
                        if client.recv(1): raise RuntimeError("client remained open after stop")
                if mode=="failure": process.terminate(); process.wait(timeout=5)
                diagnostics=process.stderr.read().decode()
                if process.returncode!=0 or "unexpected-system-resolver" in diagnostics: raise RuntimeError(diagnostics)
            finally:
                if process.poll() is None: process.kill(); process.wait(timeout=5)
# Stop two workers while several independent bootstrap requests are outstanding.
with tempfile.TemporaryDirectory(prefix="nexus-vless-bootstrap-stop-") as directory:
    root=pathlib.Path(directory); cert=root/"cert"; key=root/"key"; uuid=root/"uuid"
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,
                    "-subj","/CN=localhost","-days","1"],check=True,capture_output=True,timeout=10)
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket() as reserved:
        dns.bind(("127.0.0.1",0)); dns.settimeout(5)
        reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]; reserved.close()
        config=root/"proxy.kdl"
        config.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; disable-cache #true; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ bootstrap-resolver "boot"; server host="edge.test" port=443; authentication {{ uuid-file "{uuid}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}; }}
routing {{ default-outbound "edge"; }}
''')
        env=os.environ.copy(); env["LD_PRELOAD"]=str(guard)
        process=subprocess.Popen([binary,"run","--config",config],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        clients=[]
        try:
            deadline=time.monotonic()+5
            while True:
                if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.2): break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            for _ in range(16):
                client=socket.create_connection(("127.0.0.1",port),timeout=5); clients.append(client)
                client.settimeout(5); client.sendall(b"\x05\x01\x00")
                if exact(client,2)!=b"\x05\x00": raise RuntimeError("SOCKS negotiation failed")
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2")
            for _ in clients:
                query,_=dns.recvfrom(512)
                if query[12:]!=b"\x04edge\x04test\x00\x00\x01\x00\x01": raise RuntimeError("wrong DNS query")
            process.terminate(); process.wait(timeout=5)
            for client in clients:
                if client.recv(1): raise RuntimeError("client remained open after stop")
            diagnostics=process.stderr.read().decode()
            if process.returncode!=0 or "unexpected-system-resolver" in diagnostics: raise RuntimeError(diagnostics)
        finally:
            for client in clients: client.close()
            if process.poll() is None: process.kill(); process.wait(timeout=5)
print("VLESS bootstrap failure and cancellation passed without system DNS")
