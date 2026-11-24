#!/usr/bin/env python3
"""Authenticated SOCKS identities drive TCP and UDP routing after verification."""
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

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

def connect(port,user,password=b'secret'):
    s=socket.create_connection(('127.0.0.1',port),timeout=3); s.settimeout(3)
    method=2 if user else 0
    s.sendall(bytes((5,1,method)))
    if exact(s,2)!=bytes((5,method)): raise RuntimeError('SOCKS method')
    if user:
        s.sendall(bytes((1,len(user)))+user+bytes((len(password),))+password)
        if exact(s,2)!=b'\x01\x00': s.close(); raise PermissionError('authentication rejected')
    return s

with tempfile.TemporaryDirectory(prefix='nexus-auth-rules-') as directory:
    root=pathlib.Path(directory); reservations=[reserve() for _ in range(3)]
    ports=[s.getsockname()[1] for s in reservations]
    for s in reservations: s.close()
    password=root/'password'; password.write_text('secret\n'); password.chmod(0o600)
    (root/'rules.kdl').write_text('''schema-version 2
kind "predicate"
rule type="auth-user" value="alice"
rule type="not" { rule type="auth-user" value="bob"; }
''')
    (root/'config.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{
 socks5 "alice" {{ listen host="127.0.0.1" port={ports[0]}; authentication "password" username="alice" password-file="{password}"; }}
 socks5 "bob" {{ listen host="127.0.0.1" port={ports[1]}; authentication "password" username="bob" password-file="{password}"; }}
 socks5 "anonymous" {{ listen host="127.0.0.1" port={ports[2]}; authentication "none"; }}
}}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rule-set "users" path="rules.kdl" format="kdl"; rules {{ - kind="rule-set" value="users" outbound="reject"; }}; default-outbound "direct"; }}
''')
    server=subprocess.Popen([binary,'run','--config',root/'config.kdl'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        for port in ports:
            deadline=time.monotonic()+10
            while True:
                if server.poll() is not None: raise RuntimeError(f'server exited: {server.stderr.read()!r}')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                except OSError:
                    if time.monotonic()>deadline: raise
                    time.sleep(.02)
        try: connect(ports[0],b'alice',b'wrong')
        except PermissionError: pass
        else: raise RuntimeError('wrong password accepted')
        with reserve() as target:
            target.listen(4); target.settimeout(3); destination=target.getsockname()[1]
            for port,user,blocked in ((ports[0],b'alice',True),(ports[1],b'bob',False),(ports[2],None,False)):
                for domain in (False,True):
                    with connect(port,user) as s:
                        address=b'\x03\x09localhost' if domain else b'\x01\x7f\x00\x00\x01'
                        s.sendall(b'\x05\x01\x00'+address+destination.to_bytes(2,'big'))
                        response=exact(s,10)
                        if response[1]!=(2 if blocked else 0): raise RuntimeError(f'TCP identity route: {response!r}')
                        if blocked:
                            if select.select([target],[],[],.1)[0]: raise RuntimeError('blocked TCP reached target')
                        else:
                            with target.accept()[0] as peer:
                                s.sendall(b'ping'); peer.settimeout(3)
                                if exact(peer,4)!=b'ping': raise RuntimeError('TCP data')
                                peer.sendall(b'pong')
                                if exact(s,4)!=b'pong': raise RuntimeError('TCP reply')
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as target:
            target.bind(('127.0.0.1',0)); target.settimeout(.35)
            for port,user,blocked in ((ports[0],b'alice',True),(ports[1],b'bob',False),(ports[2],None,False)):
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client, connect(port,user) as control:
                    client.bind(('127.0.0.1',0)); client.settimeout(3)
                    control.sendall(b'\x05\x03\x00\x01\x7f\x00\x00\x01'+client.getsockname()[1].to_bytes(2,'big'))
                    reply=exact(control,10)
                    if reply[:4]!=b'\x05\x00\x00\x01': raise RuntimeError(f'UDP association: {reply!r}')
                    relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],'big'))
                    for domain in (False,True):
                        address=b'\x03\x09localhost' if domain else b'\x01\x7f\x00\x00\x01'
                        packet=b'\x00\x00\x00'+address+target.getsockname()[1].to_bytes(2,'big')+b'hello'
                        client.sendto(packet,relay)
                        target.settimeout(.35 if blocked else 3)
                        if blocked:
                            try: target.recvfrom(64)
                            except TimeoutError: pass
                            else: raise RuntimeError('blocked UDP reached target')
                        else:
                            data,peer=target.recvfrom(64)
                            if data!=b'hello': raise RuntimeError('UDP payload')
                            target.sendto(b'reply',peer)
                            if not client.recvfrom(64)[0].endswith(b'reply'): raise RuntimeError('UDP reply')
        server.terminate(); _,err=server.communicate(timeout=10)
        if server.returncode: raise RuntimeError(f'shutdown failed: {err!r}')
        print('SOCKS authenticated and anonymous TCP/UDP user routing passed')
    finally:
        if server.poll() is None: server.kill(); server.communicate()
