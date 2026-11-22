"""Configured Vision over certificate-authenticated TLS against pinned sing-box."""
from test_paths import optional_nexus
import argparse
import concurrent.futures
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--nexus',type=pathlib.Path,default=optional_nexus(),required=optional_nexus() is None)
nexus_binary=parser.parse_args().nexus
REVISION='824dbcfb4dd0a95921840b1737b950cde590241e'
if f'Revision: {REVISION}' not in subprocess.run(['sing-box','version'],check=True,capture_output=True,text=True).stdout:
    raise RuntimeError('unexpected sing-box revision')
def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); return sock.getsockname()[1]
with tempfile.TemporaryDirectory(prefix='nexus-vision-tls-') as directory:
    root=pathlib.Path(directory)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key'),'-out',str(root/'cert'),'-subj','/CN=cover.example','-addext','subjectAltName=DNS:cover.example','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    front,port=free_port(),free_port()
    while front==port: port=free_port()
    origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(16); origin.settimeout(15)
    config={'log':{'level':'warn'},'inbounds':[{'type':'vless','listen':'127.0.0.1','listen_port':front,
        'users':[{'uuid':'00010203-0405-0607-0809-0a0b0c0d0e0f','flow':'xtls-rprx-vision'}],
        'tls':{'enabled':True,'certificate_path':str(root/'cert'),'key_path':str(root/'key')}}], 'outbounds':[{'type':'direct'}]}
    (root/'box.json').write_text(json.dumps(config)); subprocess.run(['sing-box','check','-c',root/'box.json'],check=True,capture_output=True)
    uuid=root/'uuid'; uuid.write_text('00010203-0405-0607-0809-0a0b0c0d0e0f'); uuid.chmod(0o600)
    (root/'nexus.kdl').write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={front}; flow "xtls-rprx-vision"; authentication {{ uuid-file "{uuid}"; }}; tls {{ server-name "cover.example"; ca-file "{root/'cert'}"; verify #true; }}; }}
routing {{ default-outbound "edge"; }}
''')
    server=subprocess.Popen(['sing-box','run','-c',root/'box.json'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    proxy=subprocess.Popen([nexus_binary,'run','--config',root/'nexus.kdl'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    count=4; errors=[]
    def serve_one(conn):
        try:
            with conn:
                conn.settimeout(10); data=bytearray()
                while True:
                    chunk=conn.recv(16384)
                    if not chunk: break
                    data.extend(chunk)
                conn.sendall(data); conn.shutdown(socket.SHUT_WR)
        except Exception as exc: errors.append(exc)
    def accept_all():
        threads=[]
        try:
            for _ in range(count):
                conn,_=origin.accept(); t=threading.Thread(target=serve_one,args=(conn,)); t.start(); threads.append(t)
            for t in threads: t.join(12)
            if any(t.is_alive() for t in threads): errors.append(RuntimeError('origin hung'))
        except Exception as exc: errors.append(exc)
    thread=threading.Thread(target=accept_all,daemon=True); thread.start()
    try:
        deadline=time.monotonic()+10
        # The proxy may be ready before the independent sing-box process has
        # bound its listener.  Wait for both ends before sending requests.
        while True:
            if server.poll() is not None: raise RuntimeError(f'sing-box exited: {server.stderr.read()!r}')
            try:
                probe=socket.create_connection(('127.0.0.1',front),timeout=1); probe.close(); break
            except ConnectionRefusedError:
                if time.monotonic()>=deadline: raise
                time.sleep(.05)
        while True:
            if proxy.poll() is not None: raise RuntimeError(f'proxy exited: {proxy.stderr.read()!r}')
            if server.poll() is not None: raise RuntimeError(f'sing-box exited: {server.stderr.read()!r}')
            try:
                probe=socket.create_connection(('127.0.0.1',port),timeout=1); probe.close(); break
            except ConnectionRefusedError:
                if time.monotonic()>=deadline: raise
                time.sleep(.05)
        def client(index):
            with socket.create_connection(('127.0.0.1',port),timeout=10) as sock:
                sock.settimeout(15)
                def exact(size):
                    result=bytearray()
                    while len(result)<size:
                        part=sock.recv(size-len(result))
                        if not part: raise RuntimeError('unexpected EOF')
                        result.extend(part)
                    return bytes(result)
                sock.sendall(b'\x05\x01\x00')
                if exact(2)!=b'\x05\x00': raise RuntimeError('SOCKS auth failed')
                sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
                if exact(10)[:2]!=b'\x05\x00': raise RuntimeError('SOCKS connect failed')
                payload=(f'tls vision {index}:'.encode()*1500); sock.sendall(payload); sock.shutdown(socket.SHUT_WR)
                if exact(len(payload))!=payload or sock.recv(1): raise RuntimeError('data or EOF mismatch')
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool: list(pool.map(client,range(count)))
        thread.join(15)
        if thread.is_alive() or errors: raise RuntimeError(f'origin failed: {errors}')
        origin.close(); origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(2); origin.settimeout(1)
        original=(root/'nexus.kdl').read_text(); wrong_uuid=root/'wrong-uuid'; wrong_uuid.write_text('10010203-0405-0607-0809-0a0b0c0d0e0f'); wrong_uuid.chmod(0o600)
        for mode in ('certificate','uuid'):
            invalid_port=free_port()
            invalid=original.replace(f'port={port}',f'port={invalid_port}',1)
            if mode=='certificate': invalid=invalid.replace('server-name "cover.example"','server-name "incorrect.example"')
            else: invalid=invalid.replace(str(uuid),str(wrong_uuid))
            (root/'invalid.kdl').write_text(invalid)
            process=subprocess.Popen([nexus_binary,'run','--config',root/'invalid.kdl'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+10
                while True:
                    if process.poll() is not None: raise RuntimeError(f'invalid proxy exited: {process.stderr.read()!r}')
                    try: sock=socket.create_connection(('127.0.0.1',invalid_port),timeout=1); break
                    except ConnectionRefusedError:
                        if time.monotonic()>=deadline: raise
                        time.sleep(.05)
                with sock:
                    sock.settimeout(10); sock.sendall(b'\x05\x01\x00')
                    if sock.recv(2)!=b'\x05\x00': raise RuntimeError('SOCKS auth failed')
                    sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
                    reply=sock.recv(10)
                    if reply[:2]==b'\x05\x00':
                        sock.sendall(b'rejected'); sock.shutdown(socket.SHUT_WR)
                        if sock.recv(1): raise RuntimeError(f'{mode} received data')
                try: unexpected,_=origin.accept()
                except TimeoutError: pass
                else: unexpected.close(); raise RuntimeError(f'{mode} connected to origin')
            finally:
                process.terminate(); process.wait(timeout=5)
    finally:
        origin.close(); proxy.terminate(); server.terminate(); proxy.wait(timeout=5); server.wait(timeout=5)
print('Vision TLS SOCKS concurrent sessions, half-close and identity rejection passed with pinned sing-box')
