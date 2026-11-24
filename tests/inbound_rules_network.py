#!/usr/bin/env python3
"""Verify listener-specific routing for mixed TCP and authenticated SS UDP."""
import base64
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

binary, fixture = (pathlib.Path(arg).resolve() for arg in sys.argv[1:3])
mixed_only='--mixed-only' in sys.argv[3:]

def reserve():
    s=socket.socket(); s.bind(('127.0.0.1',0)); return s

def exact(sock, size):
    data=b''
    while len(data)<size:
        part=sock.recv(size-len(data))
        if not part: raise RuntimeError('unexpected SOCKS EOF')
        data+=part
    return data

with tempfile.TemporaryDirectory(prefix='nexus-inbound-rules-') as directory:
    root=pathlib.Path(directory)
    reservations=[reserve() for _ in range(4)]
    ports=[s.getsockname()[1] for s in reservations]
    for s in reservations: s.close()
    key=root/'key'; key.write_text(base64.b64encode(bytes(range(16))).decode()+'\n'); key.chmod(0o600)
    (root/'rules.kdl').write_text('''schema-version 2
kind "predicate"
rule type="inbound" value="blocked-mixed"
rule type="and" { rule type="inbound" value="blocked-ss"; rule type="network" value="udp"; }
''')
    ss_inbounds='' if mixed_only else f'''shadowsocks "blocked-ss" {{ listen host="127.0.0.1" port={ports[2]}; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}
 shadowsocks "allowed-ss" {{ listen host="127.0.0.1" port={ports[3]}; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}'''
    (root/'server.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{
 mixed "blocked-mixed" {{ listen host="127.0.0.1" port={ports[0]}; authentication "none"; }}
 mixed "allowed-mixed" {{ listen host="127.0.0.1" port={ports[1]}; authentication "none"; }}
 {ss_inbounds}
}}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rule-set "rules" path="rules.kdl" format="kdl"; rules {{ - kind="rule-set" value="rules" outbound="reject"; }}; default-outbound "direct"; }}
''')
    server=subprocess.Popen([binary,'run','--config',root/'server.kdl'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        for port in ports[:2] if mixed_only else ports:
            deadline=time.monotonic()+10
            while True:
                if server.poll() is not None: raise RuntimeError(f'server exited: {server.stderr.read()!r}')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                except OSError:
                    if time.monotonic()>deadline: raise
                    time.sleep(.02)
        with reserve() as origin:
            origin.listen(4); origin.settimeout(3); destination=origin.getsockname()[1]
            for port,blocked in ((ports[0],True),(ports[1],False)):
                for domain in (False,True):
                    with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
                        client.settimeout(3); client.sendall(b'\x05\x01\x00')
                        if exact(client,2)!=b'\x05\x00': raise RuntimeError('SOCKS greeting')
                        address=b'\x03\x09localhost' if domain else b'\x01\x7f\x00\x00\x01'
                        client.sendall(b'\x05\x01\x00'+address+destination.to_bytes(2,'big'))
                        reply=exact(client,10)
                        if reply[1]!=(2 if blocked else 0): raise RuntimeError(f'inbound route mismatch: {reply!r}')
                        if blocked:
                            if select.select([origin],[],[],.1)[0]: raise RuntimeError('blocked TCP reached origin')
                        else:
                            with origin.accept()[0] as peer:
                                client.sendall(b'hello')
                                if peer.recv(5)!=b'hello': raise RuntimeError('allowed TCP payload')
                                peer.sendall(b'world')
                                if exact(client,5)!=b'world': raise RuntimeError('allowed TCP reply')
        if not mixed_only:
            for port,mode in ((ports[2],'inbound-blocked'),(ports[3],'inbound-allowed')):
                subprocess.run([fixture,str(port),'16',mode],check=True,timeout=5)
        server.terminate(); _,err=server.communicate(timeout=10)
        if server.returncode: raise RuntimeError(f'shutdown failed: {err!r}')
        print('per-listener mixed TCP'+('' if mixed_only else ' and SS UDP')+' inbound routing passed')
    finally:
        if server.poll() is None: server.kill(); server.communicate()
