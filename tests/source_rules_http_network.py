#!/usr/bin/env python3
"""Exercise source routing for mixed HTTP and SOCKS across listeners."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary=pathlib.Path(sys.argv[1]).resolve()
def reserve():
    sock=socket.socket(); sock.bind(('127.0.0.1',0)); return sock

def read_head(sock):
    data=b''
    while b'\r\n\r\n' not in data:
        part=sock.recv(4096)
        if not part: raise RuntimeError(f'HTTP EOF: {data!r}')
        data+=part
    return data

def exact(sock, size):
    data=b''
    while len(data)<size:
        part=sock.recv(size-len(data))
        if not part: raise RuntimeError('SOCKS EOF')
        data+=part
    return data

def client(port, source_port):
    sock=socket.socket(); sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); sock.settimeout(3)
    sock.bind(('127.0.0.1',source_port)); sock.connect(('127.0.0.1',port)); return sock

with tempfile.TemporaryDirectory(prefix='nexus-source-http-') as directory:
    root=pathlib.Path(directory)
    # Binding to 127.0.0.2 distinguishes denied clients without relying on
    # ephemeral port reuse or TIME_WAIT; both addresses are real peers.
    listeners=[reserve(),reserve()]; ports=[s.getsockname()[1] for s in listeners]
    ipv6=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); ipv6.bind(('::1',0)); ipv6_port=ipv6.getsockname()[1]; ipv6.close()
    target=reserve(); target.listen(8); target.settimeout(.2); target_port=target.getsockname()[1]
    for sock in listeners: sock.close()
    (root/'rules.kdl').write_text('''schema-version 2
kind "predicate"
rule type="and" { rule type="source-ip-cidr" value="127.0.0.2/32"; rule type="source-port-range" value="1-65535"; rule type="network" value="tcp"; }
rule type="and" { rule type="source-ip-cidr" value="::1/128"; rule type="source-port-range" value="1-65535"; rule type="network" value="tcp"; }
''')
    (root/'config.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{
 mixed "first" {{ listen host="127.0.0.1" port={ports[0]}; authentication "none"; }}
 mixed "second" {{ listen host="127.0.0.1" port={ports[1]}; authentication "none"; }}
 mixed "ipv6" {{ listen host="::1" port={ipv6_port}; authentication "none"; }}
}}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rule-set "rules" path="rules.kdl" format="kdl"; rules {{ - kind="rule-set" value="rules" outbound="reject"; }}; default-outbound "direct"; }}
''')
    stop=threading.Event(); errors=[]; received=[]
    def origin():
        try:
            while not stop.is_set():
                try: conn,_=target.accept()
                except TimeoutError: continue
                with conn:
                    conn.settimeout(3); data=conn.recv(4096); received.append(data)
                    if data.startswith(b'GET '): conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
                    else: conn.sendall(data)
        except Exception as exc: errors.append(exc)
    thread=threading.Thread(target=origin); thread.start()
    server=subprocess.Popen([binary,'run','--config',root/'config.kdl'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        for port in ports:
            deadline=time.monotonic()+8
            while True:
                if server.poll() is not None: raise RuntimeError(f'server exited {server.stderr.read()!r}')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                except OSError:
                    if time.monotonic()>deadline: raise
                    time.sleep(.02)
            for connect in (False,True):
                with socket.socket() as denied:
                    denied.settimeout(3); denied.bind(('127.0.0.2',0)); denied.connect(('127.0.0.1',port))
                    request=(f'CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n' if connect else
                             f'GET http://127.0.0.1:{target_port}/ HTTP/1.1\r\nHost: example.test\r\n\r\n')
                    denied.sendall(request.encode())
                    if not read_head(denied).startswith(b'HTTP/1.1 403 '): raise RuntimeError('source-denied HTTP not blocked')
                with client(port,0) as allowed:
                    allowed.sendall(request.encode()); reply=read_head(allowed)
                    if not reply.startswith(b'HTTP/1.1 200 '): raise RuntimeError(f'allowed HTTP failed: {reply!r}')
                    if connect:
                        allowed.sendall(b'connect');
                        if allowed.recv(7)!=b'connect': raise RuntimeError('CONNECT echo')
            for domain in (False,True):
                for source,blocked in (('127.0.0.2',True),('127.0.0.1',False)):
                    with socket.socket() as sock:
                        sock.settimeout(3); sock.bind((source,0)); sock.connect(('127.0.0.1',port))
                        sock.sendall(b'\x05\x01\x00')
                        if exact(sock,2)!=b'\x05\x00': raise RuntimeError('SOCKS greeting')
                        target_address=(b'\x03\x09localhost' if domain else b'\x01\x7f\x00\x00\x01')
                        sock.sendall(b'\x05\x01\x00'+target_address+target_port.to_bytes(2,'big'))
                        reply=exact(sock,10)
                        if blocked and reply[1]!=2: raise RuntimeError(f'SOCKS source not blocked: {reply!r}')
                        if not blocked:
                            if reply[1]!=0: raise RuntimeError(f'SOCKS allowed failed: {reply!r}')
                            sock.sendall(b'socks')
                            if exact(sock,5)!=b'socks': raise RuntimeError('SOCKS echo')
        for connect in (False,True):
            with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as denied:
                denied.settimeout(3); denied.connect(('::1',ipv6_port))
                request=(f'CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n' if connect else
                         f'GET http://127.0.0.1:{target_port}/ HTTP/1.1\r\nHost: example.test\r\n\r\n')
                denied.sendall(request.encode())
                if not read_head(denied).startswith(b'HTTP/1.1 403 '): raise RuntimeError('IPv6 source-denied HTTP not blocked')
        if len(received)!=8 or errors: raise RuntimeError(f'origin received={received!r} errors={errors!r}')
        server.terminate(); _,err=server.communicate(timeout=5)
        if server.returncode: raise RuntimeError(f'shutdown: {err!r}')
        print('HTTP IPv4/IPv6 and SOCKS IPv4 source routing across listeners passed')
    finally:
        if server.poll() is None: server.kill(); server.communicate()
        stop.set(); thread.join(3); target.close()
