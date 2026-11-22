#!/usr/bin/env python3
"""Check that SS bootstrap consumes the configured TCP connection deadline."""
import base64
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

with tempfile.TemporaryDirectory(prefix='nexus-ss-timeout-') as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
    root=pathlib.Path(directory)
    key=root/'key'; key.write_text(base64.b64encode(bytes(range(16))).decode()); key.chmod(0o600)
    dns.bind(('127.0.0.1',0)); dns.settimeout(3)
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1',0)); port=reserved.getsockname()[1]
    config=root/'config.kdl'
    config.write_text(f'''schema-version 1
role "client"
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{ server host="edge.test" port=443; bootstrap-resolver "boot"; connect-timeout-ms 800; method "2022-blake3-aes-128-gcm"; key-file "{key}"; udp-over-tcp "v2"; }}
routing {{ default-outbound "edge"; }}
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
            client.settimeout(4); client.sendall(b'\x05\x01\x00')
            if exact(client,2)!=b'\x05\x00': raise RuntimeError('SOCKS negotiation failed')
            started=time.monotonic(); client.sendall(b'\x05\x01\x00\x03\x0btarget.test\x04\xd2')
            query,_=dns.recvfrom(512)
            if query[12:]!=b'\x06target\x04test\x00\x00\x01\x00\x01': raise RuntimeError('wrong target DNS query')
            reply=exact(client,10); elapsed=time.monotonic()-started
            if reply[0]!=5 or reply[1]!=6 or not .5<=elapsed<=3:
                raise RuntimeError(f'unexpected target DNS timeout: reply={reply!r}, elapsed={elapsed:.2f}s')
        with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
            client.settimeout(4); client.sendall(b'\x05\x01\x00')
            if exact(client,2)!=b'\x05\x00': raise RuntimeError('SOCKS negotiation failed')
            started=time.monotonic(); client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2')
            query,_=dns.recvfrom(512)
            if query[12:]!=b'\x04edge\x04test\x00\x00\x01\x00\x01': raise RuntimeError('wrong DNS query')
            reply=exact(client,10); elapsed=time.monotonic()-started
            if reply[0]!=5 or reply[1]!=6 or not .5<=elapsed<=3:
                raise RuntimeError(f'unexpected timeout: reply={reply!r}, elapsed={elapsed:.2f}s')
        with socket.create_connection(('127.0.0.1',port),timeout=3) as control, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            control.settimeout(4); udp.bind(('127.0.0.1',0)); control.sendall(b'\x05\x01\x00')
            if exact(control,2)!=b'\x05\x00': raise RuntimeError('SOCKS UDP negotiation failed')
            control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
            reply=exact(control,10)
            if reply[1]!=0: raise RuntimeError('SOCKS UDP association failed')
            relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],'big'))
            started=time.monotonic(); udp.sendto(b'\x00\x00\x00\x01\x7f\x00\x00\x01\x04\xd2payload',relay)
            query,_=dns.recvfrom(512)
            if query[12:]!=b'\x04edge\x04test\x00\x00\x01\x00\x01': raise RuntimeError('wrong UoT bootstrap query')
            if control.recv(1) or not .5<=time.monotonic()-started<=3:
                raise RuntimeError('UoT bootstrap did not stop at its configured deadline')
        process.terminate(); _,stderr=process.communicate(timeout=5)
        if process.returncode: raise RuntimeError(stderr.decode())
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)
print('SS TCP and UoT configured bootstrap deadlines passed')
