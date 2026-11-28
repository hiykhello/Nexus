#!/usr/bin/env python3
"""Resolve IP-dependent routes using the available outbound deadlines."""
import base64
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary=pathlib.Path(sys.argv[1]).resolve()
def exact(sock,n):
    result=bytearray()
    while len(result)<n:
        data=sock.recv(n-len(result))
        if not data: raise RuntimeError('unexpected EOF')
        result.extend(data)
    return bytes(result)

with tempfile.TemporaryDirectory(prefix='nexus-timeout-route-') as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket() as upstream:
    root=pathlib.Path(directory); key=root/'key'
    key.write_text(base64.b64encode(bytes(range(16))).decode()); key.chmod(0o600)
    (root/'rules.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.1/32"\n')
    dns.bind(('127.0.0.1',0)); dns.settimeout(4)
    upstream.bind(('127.0.0.1',0)); upstream.listen(); upstream.settimeout(4)
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1',0)); port=reserved.getsockname()[1]
    config=root/'config.kdl'; config.write_text(f'''schema-version 1
role "client"
workers 2
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct" {{ connect-timeout-ms 800; }}
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={upstream.getsockname()[1]}; connect-timeout-ms 2200; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}
routing {{ rulesets {{ "by-ip" path="rules.kdl" format="kdl"; }}; rules {{ - rule-set="by-ip" to="edge"; }}; final "direct"; }}
''')
    process=subprocess.Popen([binary,'run','--config',config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        deadline=time.monotonic()+5
        while True:
            if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2): break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        for name,ip,expected in ((b'tunnel.test',b'\x7f\x00\x00\x01',0),(b'direct.test',b'\x7f\x00\x00\x02',6)):
            with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
                client.settimeout(4); client.sendall(b'\x05\x01\x00')
                if exact(client,2)!=b'\x05\x00': raise RuntimeError('SOCKS negotiation failed')
                started=time.monotonic(); client.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+b'\x04\xd2')
                query,peer=dns.recvfrom(512); time.sleep(1.1)
                response=bytearray(query); response[2:4]=b'\x81\x80'; response[6:8]=b'\x00\x01'
                response.extend(b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04'+ip)
                dns.sendto(response,peer)
                reply=exact(client,10); elapsed=time.monotonic()-started
                if reply[1]!=expected or not 1<=elapsed<2.1:
                    raise RuntimeError(f'{name!r}: reply={reply!r}, elapsed={elapsed:.2f}')
                if expected==0:
                    with upstream.accept()[0] as peer: peer.settimeout(2); peer.recv(1024)
        process.terminate(); _,stderr=process.communicate(timeout=5)
        if process.returncode: raise RuntimeError(stderr.decode())
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)
print('IP-dependent route uses the selected outbound deadline after DNS')
