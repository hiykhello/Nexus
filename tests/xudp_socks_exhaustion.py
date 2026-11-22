#!/usr/bin/env python3
"""Exhaust all 65535 XUDP IDs through SOCKS and verify stream rotation."""
import argparse
import pathlib
import queue
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

parser=argparse.ArgumentParser()
parser.add_argument('nexus')
parser.add_argument('--ipv6',action='store_true')
parser.add_argument('--vision',action='store_true')
parser.add_argument('--stop-reconnect',action='store_true')
parser.add_argument('--start',type=int,default=1,help='initial ID of a purpose-built test binary')
args=parser.parse_args()
if not 1<=args.start<=65535: parser.error('start must be in 1..65535')
nexus=pathlib.Path(args.nexus).resolve(); ipv6=args.ipv6; vision=args.vision; start_id=args.start; stop_reconnect=args.stop_reconnect

def exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('unexpected EOF')
        data += part
    return data

class VisionStream:
    def __init__(self, sock):
        self.sock=sock; self.input=b''; self.first_read=True; self.first_write=True; self.plain=False
    def recv(self, size):
        while not self.input:
            if self.plain: return self.sock.recv(size)
            if self.first_read:
                prefix=self.sock.recv(16)
                if not prefix: return b''
                prefix+=exact(self.sock,16-len(prefix))
                if prefix!=bytes(range(16)): raise RuntimeError('wrong Vision identity')
                self.first_read=False
            head=self.sock.recv(5)
            if not head: return b''
            head+=exact(self.sock,5-len(head))
            content=int.from_bytes(head[1:3],'big'); padding=int.from_bytes(head[3:5],'big')
            self.input=exact(self.sock,content); exact(self.sock,padding)
            if head[0]==1: self.plain=True
            elif head[0]!=0: raise RuntimeError(f'unexpected Vision command {head[0]}')
        data,self.input=self.input[:size],self.input[size:]
        return data
    def sendall(self, data):
        prefix=bytes(range(16)) if self.first_write else b''; self.first_write=False
        self.sock.sendall(prefix+b'\x00'+len(data).to_bytes(2,'big')+b'\x00\x00'+data)
    def setsockopt(self,*args): self.sock.setsockopt(*args)
    def __enter__(self): return self
    def __exit__(self,*args): self.sock.close()

def frame(sock):
    length = int.from_bytes(exact(sock, 2), 'big')
    meta = exact(sock, length)
    data = exact(sock, int.from_bytes(exact(sock, 2), 'big')) if meta[3] & 1 else b''
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
    return meta, data

def response(session, kind, payload=b'', address=None):
    meta = session.to_bytes(2, 'big') + bytes([kind, bool(payload)])
    if address is not None:
        meta += b'\x02' + address
    return len(meta).to_bytes(2, 'big') + meta + (len(payload).to_bytes(2, 'big') + payload if payload else b'')

with tempfile.TemporaryDirectory(prefix='nexus-xudp-fault-') as directory:
    root = pathlib.Path(directory)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root/'key'), '-out', str(root/'cert'), '-subj', '/CN=cover.example', '-addext', 'subjectAltName=DNS:cover.example', '-days', '1'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root/'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n')
    (root/'uuid').chmod(0o600)
    with socket.socket() as listener, socket.socket() as reserve:
        listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(10)
        reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]; reserve.close()
        flow=' flow "xtls-rprx-vision";' if vision else ''
        (root/'config').write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={listener.getsockname()[1]};{flow} authentication {{ uuid-file "{root/'uuid'}"; }}; tls {{ server-name "cover.example"; ca-file "{root/'cert'}"; verify #true; }} }}
routing {{ default-outbound "edge"; }}
''')
        finished = threading.Event(); old_closed=threading.Event(); new_tcp=threading.Event(); barriers = queue.Queue(); errors = []
        def handshake(context):
            raw, _ = listener.accept()
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock = context.wrap_socket(raw, server_side=True); sock.settimeout(30)
            hello = exact(sock, 18)
            if hello[:17] != b'\x00' + bytes(range(16)): raise RuntimeError('bad VLESS identity')
            addon=exact(sock, hello[17])
            if vision and b'xtls-rprx-vision' not in addon: raise RuntimeError('missing Vision flow')
            if exact(sock, 1) != b'\x03': raise RuntimeError('expected Mux')
            sock.sendall(b'\x00\x00')
            return VisionStream(sock) if vision else sock
        def server():
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/'cert', root/'key')
                with handshake(context) as sock:
                    for session in range(start_id, 65536):
                        meta, payload = frame(sock)
                        if meta[:4] != session.to_bytes(2, 'big') + b'\x01\x01' or payload != b'probe':
                            raise RuntimeError(f'bad open {session}: {meta!r} {payload!r}')
                        sock.sendall(response(session, 2, b'ok') + response(session, 3) + response(0, 2, b'barrier'))
                        ack, payload = frame(sock)
                        if ack[:4] != b'\x00\x00\x03\x00' or payload: raise RuntimeError('end barrier failed')
                        barriers.put(session)
                    print('waiting for old stream close',flush=True)
                    if sock.recv(1): raise RuntimeError('old tunnel remained open')
                    print('old stream closed',flush=True)
                old_closed.set()
                if stop_reconnect:
                    raw,_=listener.accept(); new_tcp.set()
                    with raw:
                        if not finished.wait(10): raise RuntimeError('stop gate timed out')
                        if raw.recv(1)==b'': return
                        raw.settimeout(10)
                        while raw.recv(4096): pass
                    return
                print('waiting for new connection',flush=True)
                with handshake(context) as sock:
                    print('new TLS connection ready',flush=True)
                    meta, payload = frame(sock)
                    if meta[:4] != start_id.to_bytes(2,'big') + b'\x01\x01' or payload != b'after': raise RuntimeError('new stream did not restart at its initial session ID')
                    sock.sendall(response(start_id, 2, b'renewed'))
                    if not finished.wait(30): raise RuntimeError('finish gate timed out')
            except Exception as exc:
                errors.append(exc); print(f'fixture error: {exc!r}',flush=True); barriers.put(None); finished.set()
        thread = threading.Thread(target=server, daemon=True); thread.start()
        proxy = subprocess.Popen([nexus, 'run', '--config', root/'config'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while True:
                if proxy.poll() is not None: raise RuntimeError(f'proxy exited: {proxy.stderr.read()!r}')
                try: control = socket.create_connection(('127.0.0.1', port), timeout=1); break
                except ConnectionRefusedError:
                    if time.monotonic() > deadline: raise
                    time.sleep(.05)
            with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                control.settimeout(10); udp.settimeout(10); udp.bind(('127.0.0.1', 0))
                control.sendall(b'\x05\x01\x00'); assert exact(control, 2) == b'\x05\x00'
                control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00'); reply = exact(control, 10)
                if reply[:4] != b'\x05\x00\x00\x01': raise RuntimeError(f'association {reply!r}')
                relay = (socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:10], 'big'))
                header = b'\x00\x00\x00' + (b'\x04' + socket.inet_pton(socket.AF_INET6, '::1') if ipv6 else b'\x01\x7f\x00\x00\x01') + b'\x00\x35'
                for session in range(start_id, 65536):
                    udp.sendto(header+b'probe', relay)
                    if udp.recvfrom(65535)[0] != header+b'ok': raise RuntimeError(f'bad reply at {session}')
                    if barriers.get(timeout=30) != session: raise RuntimeError(f'barrier failed at {session}: {errors}')
                    if session % 5000 == 0: print(f'completed {session} sessions', flush=True)
                udp.sendto(header+b'after', relay)
                if stop_reconnect:
                    if not old_closed.wait(10) or not new_tcp.wait(10): raise RuntimeError(f'new TCP connection not established: {errors}')
                    proxy.terminate()
                    try: closed=control.recv(1)
                    except ConnectionResetError: closed=b''
                    if closed: raise RuntimeError('control survived shutdown')
                elif udp.recvfrom(65535)[0] != header+b'renewed': raise RuntimeError('wrong response after rotation')
                finished.set()
            thread.join(30)
            if thread.is_alive() or errors: raise RuntimeError(f'fixture failure: {errors}')
        finally:
            finished.set()
            if proxy.poll() is None: proxy.terminate()
            _, stderr = proxy.communicate(timeout=5)
            if proxy.returncode: raise RuntimeError(f'proxy exit {proxy.returncode}: {stderr!r}')
print(f'XUDP SOCKS {"stopped during reconnect" if stop_reconnect else "rotated"} after session IDs {start_id}..65535')
