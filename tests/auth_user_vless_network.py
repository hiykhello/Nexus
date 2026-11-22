#!/usr/bin/env python3
"""VLESS UUIDs map to authenticated names before TCP route selection."""
import pathlib
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

binary=pathlib.Path(sys.argv[1]).resolve()
def reserve():
    s=socket.socket(); s.bind(('127.0.0.1',0)); return s

def exact(s,n):
    data=b''
    while len(data)<n:
        part=s.recv(n-len(data))
        if not part: raise RuntimeError('unexpected EOF')
        data+=part
    return data

with tempfile.TemporaryDirectory(prefix='nexus-auth-vless-') as directory, reserve() as target:
    root=pathlib.Path(directory)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key'),'-out',str(root/'cert'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    (root/'key').chmod(0o600)
    ids=['00010203-0405-0607-0809-0a0b0c0d0e0f','10111213-1415-1617-1819-1a1b1c1d1e1f']
    for i,identity in enumerate(ids):
        path=root/f'uuid{i}'; path.write_text(identity+'\n'); path.chmod(0o600)
    with reserve() as listener: port=listener.getsockname()[1]
    target.listen(4); target.settimeout(3); destination=target.getsockname()[1]
    (root/'rules.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="auth-user" value="alice"\n')
    (root/'config.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbound "vless" type="vless" {{ listen host="127.0.0.1" port={port}; authentication {{ user "alice" uuid-file="{root/'uuid0'}"; user "bob" uuid-file="{root/'uuid1'}"; }}; tls {{ certificate-file "{root/'cert'}"; private-key-file "{root/'key'}"; }}; }}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rule-set "users" path="rules.kdl" format="kdl"; rule kind="rule-set" value="users" outbound="reject"; default-outbound "direct"; }}
''')
    server=subprocess.Popen([binary,'run','--config',root/'config.kdl'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        deadline=time.monotonic()+10
        while True:
            if server.poll() is not None: raise RuntimeError(f'server exited: {server.stderr.read()!r}')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2): break
            except OSError:
                if time.monotonic()>deadline: raise
                time.sleep(.02)
        context=ssl.create_default_context(cafile=str(root/'cert'))
        for identity,blocked in ((ids[0],True),(ids[1],False),('20212223-2425-2627-2829-2a2b2c2d2e2f',True)):
            with socket.create_connection(('127.0.0.1',port),timeout=3) as raw, context.wrap_socket(raw,server_hostname='localhost') as s:
                s.settimeout(3)
                s.sendall(b'\x00'+uuid.UUID(identity).bytes+b'\x00\x01'+destination.to_bytes(2,'big')+b'\x01\x7f\x00\x00\x01')
                if blocked:
                    try: data=s.recv(2)
                    except (ConnectionResetError,ssl.SSLError): data=b''
                    if data or select.select([target],[],[],.1)[0]: raise RuntimeError('denied VLESS user reached target')
                else:
                    if exact(s,2)!=b'\x00\x00': raise RuntimeError('VLESS response')
                    with target.accept()[0] as peer:
                        peer.settimeout(3); s.sendall(b'ping')
                        if exact(peer,4)!=b'ping': raise RuntimeError('VLESS upload')
                        peer.sendall(b'pong')
                        if exact(s,4)!=b'pong': raise RuntimeError('VLESS download')
        server.terminate(); _,err=server.communicate(timeout=10)
        if server.returncode: raise RuntimeError(f'shutdown failed: {err!r}')
        print('VLESS authenticated user mapping and TCP routing passed')
    finally:
        if server.poll() is None: server.kill(); server.communicate()
