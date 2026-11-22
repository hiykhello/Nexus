"""Exercise the Vision client against the pinned sing-box Reality server."""
from test_paths import optional_fixture, optional_nexus
import base64
import argparse
import concurrent.futures
import json
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fixture', type=pathlib.Path, default=optional_fixture('vision-reality-fixture'), required=optional_fixture('vision-reality-fixture') is None)
parser.add_argument('--nexus', type=pathlib.Path, default=optional_nexus(), required=optional_nexus() is None)
args = parser.parse_args()
FIXTURE = args.fixture.resolve()
NEXUS = args.nexus.resolve()
REVISION = '824dbcfb4dd0a95921840b1737b950cde590241e'
PAYLOAD = b'Vision Reality bidirectional payload'

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

version = subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout
if f'Revision: {REVISION}' not in version:
    raise RuntimeError('unexpected sing-box revision')
keys = subprocess.run(['sing-box', 'generate', 'reality-keypair'], check=True, capture_output=True, text=True).stdout
values = dict(line.split(': ', 1) for line in keys.splitlines() if ': ' in line)
public = base64.urlsafe_b64decode(values['PublicKey'] + '=')
with tempfile.TemporaryDirectory(prefix='nexus-vision-') as directory:
    root = pathlib.Path(directory)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key'),'-out',str(root/'cert'),'-subj','/CN=cover.example','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    backend, front = free_port(), free_port()
    while backend == front: front = free_port()
    cover = subprocess.Popen(['openssl','s_server','-quiet','-accept',str(backend),'-cert',str(root/'cert'),'-key',str(root/'key')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    origin = socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(1); origin.settimeout(12)
    config = {'log': {'level':'warn'}, 'inbounds':[{'type':'vless','listen':'127.0.0.1','listen_port':front,
        'users':[{'uuid':'00010203-0405-0607-0809-0a0b0c0d0e0f','flow':'xtls-rprx-vision'}],
        'tls':{'enabled':True,'server_name':'cover.example','reality':{'enabled':True,'handshake':{'server':'127.0.0.1','server_port':backend},'private_key':values['PrivateKey'],'short_id':['0123456789abcdef']}}}], 'outbounds':[{'type':'direct'}]}
    path=root/'config.json'; path.write_text(json.dumps(config))
    server=None; errors=[]
    def serve():
        try:
            with origin.accept()[0] as conn:
                conn.settimeout(10); data=b''
                while len(data)<len(PAYLOAD):
                    part=conn.recv(4096)
                    if not part: break
                    data+=part
                if data!=PAYLOAD: raise RuntimeError(f'bad origin data: {data!r}')
                conn.sendall(data)
        except Exception as exc: errors.append(exc)
    worker=threading.Thread(target=serve,daemon=True); worker.start()
    try:
        subprocess.run(['sing-box','check','-c',path],check=True,capture_output=True)
        server=subprocess.Popen(['sing-box','run','-c',path],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        time.sleep(.5)
        if server.poll() is not None or cover.poll() is not None: raise RuntimeError('fixture server exited')
        result=subprocess.run([FIXTURE,str(front),public.hex(),str(origin.getsockname()[1])],capture_output=True,timeout=15)
        worker.join(12)
        if result.returncode or worker.is_alive() or errors:
            server.terminate(); _,log=server.communicate(timeout=5); server=None
            raise RuntimeError(f'fixture exit {result.returncode}, origin {errors}, alive {worker.is_alive()}, server: {log.decode(errors="replace")}')
        origin.close()
        origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(1); origin.settimeout(12)
        listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(1)
        inner_payload=bytes(range(256))*256
        errors=[]
        def serve_tls():
            try:
                tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.minimum_version=ssl.TLSVersion.TLSv1_3
                tls.load_cert_chain(root/'cert',root/'key')
                with origin.accept()[0] as conn:
                    conn.settimeout(12)
                    with tls.wrap_socket(conn,server_side=True) as stream:
                        data=b''
                        while len(data)<len(inner_payload):
                            part=stream.recv(16384)
                            if not part: break
                            data+=part
                        if data!=inner_payload: raise RuntimeError(f'bad TLS payload length {len(data)}')
                        stream.sendall(data)
                        stream.unwrap().close()
            except Exception as exc: errors.append(exc)
        worker=threading.Thread(target=serve_tls,daemon=True); worker.start()
        fixture=subprocess.Popen([FIXTURE,str(front),public.hex(),str(origin.getsockname()[1]),str(listener.fileno())],pass_fds=(listener.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            tls=ssl.create_default_context(cafile=str(root/'cert')); tls.minimum_version=ssl.TLSVersion.TLSv1_3
            with socket.create_connection(listener.getsockname(),timeout=10) as conn:
                conn.settimeout(15)
                with tls.wrap_socket(conn,server_hostname='cover.example') as stream:
                    stream.sendall(inner_payload); received=b''
                    while len(received)<len(inner_payload):
                        part=stream.recv(16384)
                        if not part: break
                        received+=part
                    if received!=inner_payload: raise RuntimeError(f'bad TLS response length {len(received)}')
                    stream.unwrap().close()
            out,err=fixture.communicate(timeout=15); worker.join(12)
            if fixture.returncode or errors or worker.is_alive() or b'send_direct=1 receive_direct=1' not in err:
                raise RuntimeError(f'inner TLS fixture exit {fixture.returncode}, log {err!r}, origin {errors}, alive {worker.is_alive()}')
        finally:
            listener.close()
            if fixture.poll() is None: fixture.kill()
            fixture.communicate()
        origin.close()
        origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(1); origin.settimeout(12)
        errors=[]; worker=threading.Thread(target=serve_tls,daemon=True); worker.start()
        proxy_port=free_port(); uuid=root/'uuid'; uuid.write_text('00010203-0405-0607-0809-0a0b0c0d0e0f'); uuid.chmod(0o600)
        config_path=root/'nexus.kdl'
        fast_open='tcp-fast-open #true;' if os.getenv('NEXUS_TEST_FAST_OPEN') else ''
        config_path.write_text(f"""schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={proxy_port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
 server host="127.0.0.1" port={front}
 flow "xtls-rprx-vision"
 authentication {{ uuid-file "{uuid}"; }}
 tls {{ server-name "cover.example"; reality {{ public-key "{public.hex()}"; short-id "0123456789abcdef"; }}; }}
 {fast_open}
}}
routing {{ default-outbound "edge"; }}
""")
        proxy=subprocess.Popen([NEXUS,'run','--config',config_path],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+10
            while True:
                if proxy.poll() is not None: raise RuntimeError(f'proxy exited: {proxy.stderr.read()!r}')
                try: conn=socket.create_connection(('127.0.0.1',proxy_port),timeout=1); break
                except ConnectionRefusedError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.05)
            with conn:
                conn.settimeout(15)
                def exact(n):
                    data=b''
                    while len(data)<n:
                        part=conn.recv(n-len(data))
                        if not part: raise RuntimeError('SOCKS closed')
                        data+=part
                    return data
                conn.sendall(b'\x05\x01\x00')
                if exact(2)!=b'\x05\x00': raise RuntimeError('SOCKS auth failed')
                conn.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
                if exact(10)[:2]!=b'\x05\x00': raise RuntimeError('SOCKS connect failed')
                tls=ssl.create_default_context(cafile=str(root/'cert')); tls.minimum_version=ssl.TLSVersion.TLSv1_3
                with tls.wrap_socket(conn,server_hostname='cover.example') as stream:
                    stream.sendall(inner_payload); received=b''
                    while len(received)<len(inner_payload):
                        part=stream.recv(16384)
                        if not part: break
                        received+=part
                    if received!=inner_payload: raise RuntimeError(f'bad proxy TLS response length {len(received)}')
                    stream.unwrap().close()
            worker.join(12)
            if worker.is_alive() or errors: raise RuntimeError(f'proxy origin failed {errors}, alive {worker.is_alive()}')
            origin.close(); origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(16); origin.settimeout(15)
            target_port=origin.getsockname()[1]; count=8; errors=[]
            def echo_one(peer):
                try:
                    with peer:
                        peer.settimeout(12); data=bytearray()
                        while True:
                            part=peer.recv(8192)
                            if not part: break
                            data.extend(part)
                        peer.sendall(data); peer.shutdown(socket.SHUT_WR)
                except Exception as exc: errors.append(exc)
            def accept_many():
                threads=[]
                try:
                    for _ in range(count):
                        conn,_=origin.accept(); thread=threading.Thread(target=echo_one,args=(conn,)); thread.start(); threads.append(thread)
                    for thread in threads: thread.join(15)
                    if any(thread.is_alive() for thread in threads): errors.append(RuntimeError('origin threads hung'))
                except Exception as exc: errors.append(exc)
            worker=threading.Thread(target=accept_many,daemon=True); worker.start()
            def client_session(index):
                with socket.create_connection(('127.0.0.1',proxy_port),timeout=10) as sock:
                    sock.settimeout(15)
                    def read_exact(n):
                        data=b''
                        while len(data)<n:
                            part=sock.recv(n-len(data))
                            if not part: raise RuntimeError(f'client {index} early EOF')
                            data+=part
                        return data
                    sock.sendall(b'\x05\x01\x00')
                    if read_exact(2)!=b'\x05\x00': raise RuntimeError('SOCKS auth failed')
                    sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+target_port.to_bytes(2,'big'))
                    if read_exact(10)[:2]!=b'\x05\x00': raise RuntimeError('SOCKS connect failed')
                    payload=(f'vision concurrent {index}:'.encode()*900)
                    sock.sendall(payload); sock.shutdown(socket.SHUT_WR)
                    if read_exact(len(payload))!=payload or sock.recv(1): raise RuntimeError(f'client {index} data or EOF mismatch')
            with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
                list(pool.map(client_session,range(count)))
            worker.join(15)
            if worker.is_alive() or errors: raise RuntimeError(f'concurrent origin failed {errors}, alive {worker.is_alive()}')
            origin.close(); origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(1); origin.settimeout(10)
            stalled=socket.create_connection(('127.0.0.1',proxy_port),timeout=10); stalled.settimeout(10)
            try:
                stalled.sendall(b'\x05\x01\x00')
                if stalled.recv(2)!=b'\x05\x00': raise RuntimeError('stalled SOCKS auth failed')
                stalled.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
                reply=b''
                while len(reply)<10:
                    part=stalled.recv(10-len(reply))
                    if not part: raise RuntimeError('stalled SOCKS closed')
                    reply+=part
                if reply[:2]!=b'\x05\x00': raise RuntimeError('stalled SOCKS connect failed')
                stalled.sendall(b'hold')
                peer,_=origin.accept(); peer.settimeout(10)
                try:
                    if peer.recv(4)!=b'hold': raise RuntimeError('stalled origin data mismatch')
                    proxy.terminate(); proxy.wait(timeout=5)
                    if proxy.returncode!=0: raise RuntimeError(f'proxy shutdown failed: {proxy.returncode}')
                    if stalled.recv(1) or peer.recv(1): raise RuntimeError('stalled sockets survived shutdown')
                finally: peer.close()
            finally: stalled.close()
        finally:
            if proxy.poll() is None: proxy.terminate(); proxy.wait(timeout=5)
    finally:
        origin.close()
        if server: server.terminate(); server.wait(timeout=5)
        cover.terminate(); cover.wait(timeout=5)
print('Vision Reality SOCKS TLS, concurrent half-close and shutdown passed with pinned sing-box')
