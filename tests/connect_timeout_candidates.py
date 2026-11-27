#!/usr/bin/env python3
"""A timed-out direct address must not hide a later longer-lived tunnel."""
import base64
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

with tempfile.TemporaryDirectory(prefix='nexus-timeout-candidates-') as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket() as upstream, socket.socket() as dead:
    root=pathlib.Path(directory); key=root/'key'
    key.write_text(base64.b64encode(bytes(range(16))).decode()); key.chmod(0o600)
    (root/'rules.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="10.88.0.3/32"\n')
    (root/'short.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="10.88.0.4/32"\n')
    (root/'dead.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="10.88.0.5/32"\n')
    (root/'short2.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="10.88.0.6/32"\n')
    dns.bind(('127.0.0.1',0)); dns.settimeout(3)
    upstream.bind(('127.0.0.1',0)); upstream.listen(); upstream.settimeout(3)
    dead.bind(('127.0.0.1',0))
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1',0)); port=reserved.getsockname()[1]
    config=root/'config.kdl'; config.write_text(f'''schema-version 1
role "client"
workers 2
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct" {{ connect-timeout-ms 800; }}
outbound "short" type="shadowsocks" {{ server host="short-node.test" port={upstream.getsockname()[1]}; bootstrap-resolver "dns"; connect-timeout-ms 400; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}
outbound "short2" type="shadowsocks" {{ server host="other-node.test" port={upstream.getsockname()[1]}; bootstrap-resolver "dns"; connect-timeout-ms 400; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={upstream.getsockname()[1]}; connect-timeout-ms 2500; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}
outbound "dead" type="shadowsocks" {{ server host="127.0.0.1" port={dead.getsockname()[1]}; connect-timeout-ms 2500; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}
routing {{ rulesets {{ "short" path="short.kdl" format="kdl"; "short2" path="short2.kdl" format="kdl"; "by-ip" path="rules.kdl" format="kdl"; "dead" path="dead.kdl" format="kdl"; }}; rules {{ - kind="rule-set" value="short" outbound="short"; - kind="rule-set" value="short2" outbound="short2"; - kind="rule-set" value="by-ip" outbound="edge"; - kind="rule-set" value="dead" outbound="dead"; }}; final "direct"; }}
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
            query,peer=dns.recvfrom(512)
            response=bytearray(query); response[2:4]=b'\x81\x80'; response[6:8]=b'\x00\x03'
            for ip in (b'\x0a\x58\x00\x02',b'\x0a\x58\x00\x04',b'\x0a\x58\x00\x03'):
                response.extend(b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04'+ip)
            dns.sendto(response,peer)
            reply=exact(client,10); elapsed=time.monotonic()-started
            if reply[1]!=0 or not .5<=elapsed<=2:
                raise RuntimeError(f'candidate fallback: reply={reply!r}, elapsed={elapsed:.2f}s')
            with upstream.accept()[0] as peer:
                peer.settimeout(2)
                if not peer.recv(1024): raise RuntimeError('tunnel request missing')
        with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
            client.settimeout(4); client.sendall(b'\x05\x01\x00')
            if exact(client,2)!=b'\x05\x00': raise RuntimeError('SOCKS negotiation failed')
            name=b'shortcase.test'
            started=time.monotonic(); client.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+b'\x04\xd2')
            query,peer=dns.recvfrom(512)
            response=bytearray(query); response[2:4]=b'\x81\x80'; response[6:8]=b'\x00\x02'
            for ip in (b'\x0a\x58\x00\x04',b'\x0a\x58\x00\x03'):
                response.extend(b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04'+ip)
            dns.sendto(response,peer)
            bootstrap,_=dns.recvfrom(512)
            if bootstrap[12:]!=b'\x0ashort-node\x04test\x00\x00\x01\x00\x01':
                raise RuntimeError('wrong short tunnel bootstrap query')
            reply=exact(client,10); elapsed=time.monotonic()-started
            if reply[1]!=0 or not .2<=elapsed<=2:
                raise RuntimeError(f'tunnel timeout fallback: reply={reply!r}, elapsed={elapsed:.2f}s')
            with upstream.accept()[0] as peer:
                peer.settimeout(2)
                if not peer.recv(1024): raise RuntimeError('second tunnel request missing')
        with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
            client.settimeout(4); client.sendall(b'\x05\x01\x00')
            if exact(client,2)!=b'\x05\x00': raise RuntimeError('SOCKS negotiation failed')
            name=b'failed.test'; started=time.monotonic()
            client.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+b'\x04\xd2')
            query,peer=dns.recvfrom(512)
            response=bytearray(query); response[2:4]=b'\x81\x80'; response[6:8]=b'\x00\x02'
            for ip in (b'\x0a\x58\x00\x02',b'\x0a\x58\x00\x05'):
                response.extend(b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04'+ip)
            dns.sendto(response,peer)
            reply=exact(client,10); elapsed=time.monotonic()-started
            if reply[1]!=6 or not .5<=elapsed<=2:
                raise RuntimeError(f'timeout overwritten by later failure: reply={reply!r}, elapsed={elapsed:.2f}s')
        with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
            client.settimeout(4); client.sendall(b'\x05\x01\x00')
            if exact(client,2)!=b'\x05\x00': raise RuntimeError('SOCKS negotiation failed')
            name=b'failure2.test'; started=time.monotonic()
            client.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+dead.getsockname()[1].to_bytes(2,'big'))
            query,peer=dns.recvfrom(512)
            response=bytearray(query); response[2:4]=b'\x81\x80'; response[6:8]=b'\x00\x02'
            for ip in (b'\x0a\x58\x00\x06',b'\x7f\x00\x00\x01'):
                response.extend(b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04'+ip)
            dns.sendto(response,peer)
            bootstrap,_=dns.recvfrom(512)
            if bootstrap[12:]!=b'\x0aother-node\x04test\x00\x00\x01\x00\x01':
                raise RuntimeError('wrong second short tunnel bootstrap query')
            reply=exact(client,10); elapsed=time.monotonic()-started
            if reply[1]!=6 or not .2<=elapsed<=2:
                raise RuntimeError(f'timeout overwritten by direct failure: reply={reply!r}, elapsed={elapsed:.2f}s')
        with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
            client.settimeout(4); client.sendall(b'\x05\x01\x00')
            if exact(client,2)!=b'\x05\x00': raise RuntimeError('SOCKS negotiation failed')
            client.sendall(b'\x05\x01\x00\x03\x09stop.test\x04\xd2')
            query,peer=dns.recvfrom(512)
            response=bytearray(query); response[2:4]=b'\x81\x80'; response[6:8]=b'\x00\x03'
            for ip in (b'\x0a\x58\x00\x02',b'\x0a\x58\x00\x04',b'\x0a\x58\x00\x03'):
                response.extend(b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04'+ip)
            dns.sendto(response,peer); time.sleep(.2)
            process.terminate(); _,stderr=process.communicate(timeout=5)
            if client.recv(1): raise RuntimeError('client survived server shutdown')
            upstream.settimeout(.2)
            try: late=upstream.accept()
            except TimeoutError: pass
            else:
                late[0].close(); raise RuntimeError('late tunnel connected after shutdown')
        if process.returncode: raise RuntimeError(stderr.decode())
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)
print('timed-out candidates fall through to later tunnel; shutdown drains pending connect')
