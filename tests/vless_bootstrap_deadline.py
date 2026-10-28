#!/usr/bin/env python3
"""A slow bootstrap and TLS handshake must share the session deadline."""
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary=pathlib.Path(sys.argv[1]).resolve()
guard=pathlib.Path(sys.argv[2]).resolve()

def exact(sock,n):
    result=bytearray()
    while len(result)<n:
        part=sock.recv(n-len(result))
        if not part: raise RuntimeError("unexpected EOF")
        result.extend(part)
    return bytes(result)

with tempfile.TemporaryDirectory(prefix="nexus-vless-bootstrap-deadline-") as directory:
    root=pathlib.Path(directory); cert=root/"cert"; key=root/"key"; uuid=root/"uuid"
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,
                    "-subj","/CN=localhost","-days","1"],check=True,capture_output=True,timeout=10)
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket() as upstream, socket.socket() as reserved:
        dns.bind(("127.0.0.1",0)); dns.settimeout(5)
        upstream.bind(("127.0.0.1",0)); upstream.listen(1); upstream.settimeout(5)
        reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]; reserved.close()
        config=root/"proxy.kdl"
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ bootstrap-resolver "boot"; server host="edge.test" port={upstream.getsockname()[1]}; authentication {{ uuid-file "{uuid}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}; }}
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
                client.settimeout(14); started=time.monotonic(); client.sendall(b"\x05\x01\x00")
                if exact(client,2)!=b"\x05\x00": raise RuntimeError("SOCKS negotiation failed")
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2")
                query,source=dns.recvfrom(512)
                if query[12:]!=b"\x04edge\x04test\x00\x00\x01\x00\x01": raise RuntimeError("wrong bootstrap query")
                time.sleep(7)
                answer=bytearray(query); answer[2:4]=b"\x81\x80"; answer[7]=1
                answer.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                dns.sendto(answer,source)
                with upstream.accept()[0] as peer:
                    peer.settimeout(5)
                    header=exact(peer,5)
                    if header[0]!=22 or not exact(peer,int.from_bytes(header[3:5],"big")): raise RuntimeError("no ClientHello")
                    response=bytearray()
                    while True:
                        part=client.recv(1024)
                        if not part: break
                        response.extend(part)
                    elapsed=time.monotonic()-started
                    if len(response)>=2 and response[:2]==b"\x05\x00": raise RuntimeError("reported success")
                    if not 8.5<=elapsed<=12: raise RuntimeError(f"session deadline was {elapsed:.2f}s")
                    if peer.recv(1): raise RuntimeError("upstream remained open")
            process.terminate(); process.wait(timeout=5)
            diagnostics=process.stderr.read().decode()
            if process.returncode!=0 or "unexpected-system-resolver" in diagnostics: raise RuntimeError(diagnostics)
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=5)
print("VLESS bootstrap and TLS share the session deadline")
