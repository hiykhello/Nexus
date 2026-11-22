#!/usr/bin/env python3
"""Check XUDP source authorization and protocol failure through SS UoT ingress."""
import base64
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
stop=len(sys.argv)==3 and sys.argv[2]=='--stop'
end=len(sys.argv)==3 and sys.argv[2]=='--end'
empty=len(sys.argv)==3 and sys.argv[2]=='--empty'
if len(sys.argv) not in (2,3) or (len(sys.argv)==3 and not (stop or end or empty)): raise SystemExit('usage: xudp_uot_inbound_faults.py NEXUS [--stop|--end|--empty]')
fixture=nexus.with_name('nexus-proxy-uot-fixture')
def exact(sock,n):
    data=b''
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part: raise RuntimeError('unexpected EOF')
        data+=part
    return data
def response(session,payload,address=None):
    meta=session.to_bytes(2,'big')+b'\x02\x01'
    if address: meta+=b'\x02'+address
    return len(meta).to_bytes(2,'big')+meta+len(payload).to_bytes(2,'big')+payload
with tempfile.TemporaryDirectory(prefix='nexus-xudp-uot-fault-') as directory:
    root=pathlib.Path(directory)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'tls-key'),'-out',str(root/'cert'),'-subj','/CN=cover.example','-addext','subjectAltName=DNS:cover.example','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    (root/'key').write_text(base64.b64encode(bytes(range(16))).decode()); (root/'key').chmod(0o600)
    (root/'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n'); (root/'uuid').chmod(0o600)
    with socket.socket() as listener,socket.socket() as reserve:
        listener.bind(('127.0.0.1',0)); listener.listen(1); listener.settimeout(10)
        reserve.bind(('127.0.0.1',0)); port=reserve.getsockname()[1]; reserve.close()
        (root/'config').write_text(f'''schema-version 1
role "server"
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={listener.getsockname()[1]}; authentication {{ uuid-file "{root/'uuid'}"; }}; tls {{ server-name "cover.example"; ca-file "{root/'cert'}"; verify #true; }} }}
routing {{ default-outbound "edge"; }}
''')
        gate=threading.Event(); barrier=threading.Event(); finished=threading.Event(); errors=[]
        def serve():
            try:
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/'cert',root/'tls-key')
                raw,_=listener.accept()
                with context.wrap_socket(raw,server_side=True) as sock:
                    sock.settimeout(10); hello=exact(sock,18)
                    if hello[:17]!=b'\x00'+bytes(range(16)): raise RuntimeError('wrong identity')
                    exact(sock,hello[17])
                    if exact(sock,1)!=b'\x03': raise RuntimeError('expected Mux')
                    sock.sendall(b'\x00\x00')
                    meta=exact(sock,int.from_bytes(exact(sock,2),'big'))
                    payload=exact(sock,int.from_bytes(exact(sock,2),'big'))
                    if meta[:4]!=b'\x00\x01\x01\x01' or payload!=(b'' if empty else b'probe'): raise RuntimeError(f'bad open {meta!r} {payload!r}')
                    forged=b'\x00\x35\x01\x7f\x00\x00\x02'
                    if empty:
                        sock.sendall(response(1,b'good'))
                        if not finished.wait(10): raise RuntimeError('fixture not finished')
                        return
                    if end:
                        sock.sendall(response(1,b'forged',forged)+response(1,b'good')+b'\x00\x04\x00\x01\x03\x00'+response(99,b'barrier'))
                        ack=exact(sock,int.from_bytes(exact(sock,2),'big'))
                        if ack!=b'\x00\x63\x03\x00': raise RuntimeError('end barrier failed')
                        barrier.set()
                        meta=exact(sock,int.from_bytes(exact(sock,2),'big'))
                        payload=exact(sock,int.from_bytes(exact(sock,2),'big'))
                        if meta[:4]!=b'\x00\x02\x01\x01' or payload!=b'probe': raise RuntimeError(f'bad reopened session {meta!r} {payload!r}')
                        sock.sendall(response(2,b'good'))
                        if not finished.wait(10): raise RuntimeError('fixture not finished')
                        return
                    sock.sendall(response(1,b'forged',forged)+response(1,b'good'))
                    if not gate.wait(10): raise RuntimeError('fixture not ready')
                    if not stop: sock.sendall(b'\x00\x03')
                    if sock.recv(1): raise RuntimeError('stream not closed')
            except Exception as exc: errors.append(exc); barrier.set()
        thread=threading.Thread(target=serve,daemon=True); thread.start()
        server=subprocess.Popen([nexus,'run','--config',root/'config'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        client=None
        try:
            deadline=time.monotonic()+10
            while True:
                if server.poll() is not None: raise RuntimeError(f'server exited: {server.stderr.read()!r}')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                except OSError:
                    if time.monotonic()>deadline: raise
                    time.sleep(.02)
            client=subprocess.Popen([fixture,str(port),'53','0','g' if empty else 'e' if end else 'd'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            if empty:
                client.wait(timeout=10); finished.set(); _,stderr=client.communicate(timeout=10)
                if client.returncode: raise RuntimeError(f'empty probe exit {client.returncode}: {stderr}')
                thread.join(10)
                if thread.is_alive() or errors: raise RuntimeError(f'peer failure: {errors}')
            else:
                line=client.stdout.readline()
                if line!='ready\n': raise RuntimeError(f'probe failed: {line!r} {client.stderr.read()!r}')
                if end:
                    if not barrier.wait(10) or errors: raise RuntimeError(f'end barrier: {errors}')
                    client.stdin.write('x'); client.stdin.flush()
                if stop: server.terminate()
                gate.set(); client.wait(timeout=10); finished.set(); _,stderr=client.communicate(timeout=10)
                if client.returncode: raise RuntimeError(f'probe exit {client.returncode}: {stderr}')
                thread.join(10)
                if thread.is_alive() or errors: raise RuntimeError(f'peer failure: {errors}')
            if not stop and server.poll() is not None: raise RuntimeError('server exited after fault')
        finally:
            gate.set(); finished.set()
            if client and client.poll() is None: client.kill(); client.communicate()
            if server.poll() is None: server.terminate()
            _,stderr=server.communicate(timeout=5)
            if server.returncode: raise RuntimeError(f'server exit {server.returncode}: {stderr!r}')
print('SS UoT -> XUDP ' + ('carries an empty datagram' if empty else 'rejects forged replies and ' + ('reopens after peer end' if end else 'closes on server stop' if stop else 'closes on malformed frames')))
