#!/usr/bin/env python3
"""Exercise an actual pending direct TCP connect in an isolated network."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary=pathlib.Path(sys.argv[1]).resolve()
if '--inner' not in sys.argv:
    subprocess.run(['unshare','-Urn',sys.executable,__file__,str(binary),'--inner'],check=True,timeout=20)
    sys.exit(0)
for args in (['link','set','lo','up'], ['link','add','nxv0','type','veth','peer','name','nxv1'],
             ['link','set','nxv0','up'], ['link','set','nxv1','up'], ['addr','add','10.88.0.1/24','dev','nxv0']):
    subprocess.run(['ip',*args],check=True,capture_output=True)

def exact(sock,n):
    data=bytearray()
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part: raise RuntimeError('unexpected EOF')
        data.extend(part)
    return bytes(data)

with tempfile.TemporaryDirectory(prefix='nexus-direct-connect-') as directory:
    root=pathlib.Path(directory)
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1',0)); port=reserved.getsockname()[1]
    config=root/'config.kdl'; config.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct" {{ connect-timeout-ms 800; }}
routing {{ final "direct"; }}
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
            started=time.monotonic(); client.sendall(b'\x05\x01\x00\x01\x0a\x58\x00\x02\x04\xd2')
            reply=exact(client,10); elapsed=time.monotonic()-started
            if reply[1]!=6 or not .5<=elapsed<=3:
                raise RuntimeError(f'pending connect: reply={reply!r}, elapsed={elapsed:.2f}s')
        process.terminate(); _,stderr=process.communicate(timeout=5)
        if process.returncode: raise RuntimeError(stderr.decode())
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)
print('direct pending TCP connect uses its configured deadline')
