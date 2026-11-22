#!/usr/bin/env python3
"""Exercise direct outbound deadlines while target DNS is pending."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary=pathlib.Path(sys.argv[1]).resolve()

def exact(sock, size):
    data=bytearray()
    while len(data)<size:
        part=sock.recv(size-len(data))
        if not part: raise RuntimeError('unexpected EOF')
        data.extend(part)
    return bytes(data)

for workers,timeout_ms in ((1,800),(2,800),(2,12000)):
    with tempfile.TemporaryDirectory(prefix='nexus-direct-timeout-') as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
        root=pathlib.Path(directory); dns.bind(('127.0.0.1',0)); dns.settimeout(4)
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1',0)); port=reserved.getsockname()[1]
        config=root/'config.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct" {{ connect-timeout-ms {timeout_ms}; }}
routing {{ default-outbound "direct"; }}
''')
        process=subprocess.Popen([binary,'run','--config',config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+5
            while True:
                if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
                try: client=socket.create_connection(('127.0.0.1',port),timeout=.2); break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            with client:
                client.settimeout(15); client.sendall(b'\x05\x01\x00')
                if exact(client,2)!=b'\x05\x00': raise RuntimeError('SOCKS negotiation failed')
                started=time.monotonic(); client.sendall(b'\x05\x01\x00\x03\x0btarget.test\x04\xd2')
                query,_=dns.recvfrom(512)
                if query[12:]!=b'\x06target\x04test\x00\x00\x01\x00\x01': raise RuntimeError('wrong target DNS query')
                reply=exact(client,10); elapsed=time.monotonic()-started
                lower,upper=(.5,3) if timeout_ms==800 else (10.5,14)
                if reply[0]!=5 or reply[1]!=6 or not lower<=elapsed<=upper:
                    raise RuntimeError(f'workers={workers}: reply={reply!r}, elapsed={elapsed:.2f}s')
            process.terminate(); _,stderr=process.communicate(timeout=5)
            if process.returncode: raise RuntimeError(stderr.decode())
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=5)
print('direct target DNS deadlines passed with one and two workers')
