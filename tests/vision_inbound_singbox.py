"""Configured Nexus Vision inbound against pinned sing-box client."""
from test_paths import optional_nexus
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
ROOT=pathlib.Path(__file__).resolve().parents[1]
REVISION='824dbcfb4dd0a95921840b1737b950cde590241e'
parser=argparse.ArgumentParser()
parser.add_argument('--nexus',type=pathlib.Path,default=optional_nexus(),required=optional_nexus() is None)
parser.add_argument('--deferred',action='store_true')
parser.add_argument('--singbox-server',action='store_true')
parser.add_argument('--nexus-client',action='store_true')
args=parser.parse_args()
deferred=args.deferred
control=args.singbox_server
nexus_client=args.nexus_client
if f'Revision: {REVISION}' not in subprocess.run(['sing-box','version'],check=True,capture_output=True,text=True).stdout: raise RuntimeError('unexpected sing-box revision')
def free_port():
    with socket.socket() as sock: sock.bind(('127.0.0.1',0)); return sock.getsockname()[1]
def exact(sock,n):
    data=bytearray()
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part: raise RuntimeError('unexpected EOF')
        data.extend(part)
    return bytes(data)
with tempfile.TemporaryDirectory(prefix='nexus-vision-inbound-') as directory:
    root=pathlib.Path(directory)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key'),'-out',str(root/'cert'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    (root/'key').chmod(0o600); uuid=root/'uuid'; uuid.write_text('00010203-0405-0607-0809-0a0b0c0d0e0f'); uuid.chmod(0o600)
    front,port=free_port(),free_port()
    while front==port: port=free_port()
    (root/'nexus.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbound "edge" type="vless" {{ listen host="127.0.0.1" port={front}; flow "xtls-rprx-vision"; authentication {{ user "test" uuid-file="{uuid}"; }}; tls {{ certificate-file "{root/'cert'}"; private-key-file "{root/'key'}"; }}; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
    config={'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':port}],
        'outbounds':[{'type':'vless','server':'127.0.0.1','server_port':front,'uuid':'00010203-0405-0607-0809-0a0b0c0d0e0f','flow':'xtls-rprx-vision','tls':{'enabled':True,'server_name':'localhost','certificate_path':str(root/'cert')}}]}
    (root/'box.json').write_text(json.dumps(config)); subprocess.run(['sing-box','check','-c',root/'box.json'],check=True,capture_output=True)
    server_config={'log':{'level':'warn'},'inbounds':[{'type':'vless','listen':'127.0.0.1','listen_port':front,'users':[{'uuid':'00010203-0405-0607-0809-0a0b0c0d0e0f','flow':'xtls-rprx-vision'}],'tls':{'enabled':True,'certificate_path':str(root/'cert'),'key_path':str(root/'key')}}],'outbounds':[{'type':'direct'}]}
    (root/'server.json').write_text(json.dumps(server_config))
    server_cmd=['sing-box','run','-c',root/'server.json'] if control else [args.nexus,'run','--config',root/'nexus.kdl']
    nexus=subprocess.Popen(server_cmd,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    fast_open='tcp-fast-open #true;' if os.getenv('NEXUS_TEST_FAST_OPEN') else ''
    (root/'client.kdl').write_text(f"""schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={front}; flow "xtls-rprx-vision"; authentication {{ uuid-file "{uuid}"; }}; tls {{ server-name "localhost"; ca-file "{root/'cert'}"; verify #true; }}; {fast_open} }}
routing {{ final "edge"; }}
""")
    client_cmd=[args.nexus,'run','--config',root/'client.kdl'] if nexus_client else ['sing-box','run','-c',root/'box.json']
    box=subprocess.Popen(client_cmd,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(16); origin.settimeout(15); errors=[]; count=4
    def serve(peer):
        try:
            with peer:
                peer.settimeout(12); data=bytearray()
                while True:
                    part=peer.recv(16384)
                    if not part: break
                    data.extend(part)
                    if not deferred: peer.sendall(part)
                if deferred: peer.sendall(data)
                peer.shutdown(socket.SHUT_WR)
        except Exception as exc: errors.append(exc)
    def accept_all():
        threads=[]
        try:
            for _ in range(count):
                peer,_=origin.accept(); t=threading.Thread(target=serve,args=(peer,)); t.start(); threads.append(t)
            for t in threads: t.join(15)
            if any(t.is_alive() for t in threads): errors.append(RuntimeError('origin hung'))
        except Exception as exc: errors.append(exc)
    worker=threading.Thread(target=accept_all,daemon=True); worker.start()
    try:
        deadline=time.monotonic()+10
        while True:
            if nexus.poll() is not None: raise RuntimeError(f'Nexus exited: {nexus.stderr.read()!r}')
            if box.poll() is not None: raise RuntimeError(f'sing-box exited: {box.stderr.read()!r}')
            try: probe=socket.create_connection(('127.0.0.1',port),timeout=1); probe.close(); break
            except ConnectionRefusedError:
                if time.monotonic()>deadline: raise
                time.sleep(.05)
        def run(index):
            with socket.create_connection(('127.0.0.1',port),timeout=10) as sock:
                sock.settimeout(15); sock.sendall(b'\x05\x01\x00')
                if exact(sock,2)!=b'\x05\x00': raise RuntimeError('SOCKS auth failed')
                sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
                if exact(sock,10)[:2]!=b'\x05\x00': raise RuntimeError('SOCKS connect failed')
                payload=(f'vision inbound {index}:'.encode()*1500); sock.sendall(payload)
                if deferred: sock.shutdown(socket.SHUT_WR)
                if exact(sock,len(payload))!=payload: raise RuntimeError('data mismatch')
                if not deferred: sock.shutdown(socket.SHUT_WR)
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool: list(pool.map(run,range(count)))
        worker.join(15)
        if worker.is_alive() or errors: raise RuntimeError(f'origin failed: {errors}')
        origin.close(); origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(1); origin.settimeout(12)
        errors=[]; tls_payload=bytes(range(256))*256
        def serve_inner_tls():
            try:
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_3; context.load_cert_chain(root/'cert',root/'key')
                with origin.accept()[0] as conn:
                    conn.settimeout(12)
                    with context.wrap_socket(conn,server_side=True) as stream:
                        data=exact(stream,len(tls_payload)); stream.sendall(data); stream.unwrap().close()
            except Exception as exc: errors.append(exc)
        worker=threading.Thread(target=serve_inner_tls,daemon=True); worker.start()
        with socket.create_connection(('127.0.0.1',port),timeout=10) as conn:
            conn.settimeout(15); conn.sendall(b'\x05\x01\x00')
            if exact(conn,2)!=b'\x05\x00': raise RuntimeError('SOCKS auth failed')
            conn.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
            if exact(conn,10)[:2]!=b'\x05\x00': raise RuntimeError('SOCKS connect failed')
            context=ssl.create_default_context(cafile=str(root/'cert')); context.minimum_version=ssl.TLSVersion.TLSv1_3
            with context.wrap_socket(conn,server_hostname='localhost') as stream:
                stream.sendall(tls_payload)
                if exact(stream,len(tls_payload))!=tls_payload: raise RuntimeError('inner TLS mismatch')
                stream.unwrap().close()
        worker.join(15)
        if worker.is_alive() or errors: raise RuntimeError(f'inner TLS origin failed: {errors}')
        if not control:
            origin.close(); origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(2); origin.settimeout(1)
            for mode in ('wrong-user','no-flow'):
                invalid_port=free_port(); invalid=json.loads(json.dumps(config)); invalid['inbounds'][0]['listen_port']=invalid_port
                if mode=='wrong-user': invalid['outbounds'][0]['uuid']='10010203-0405-0607-0809-0a0b0c0d0e0f'
                else: del invalid['outbounds'][0]['flow']
                (root/'invalid.json').write_text(json.dumps(invalid))
                invalid_box=subprocess.Popen(['sing-box','run','-c',root/'invalid.json'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                try:
                    deadline=time.monotonic()+10
                    while True:
                        if invalid_box.poll() is not None: raise RuntimeError(f'invalid client exited: {invalid_box.stderr.read()!r}')
                        try: sock=socket.create_connection(('127.0.0.1',invalid_port),timeout=1); break
                        except ConnectionRefusedError:
                            if time.monotonic()>deadline: raise
                            time.sleep(.05)
                    with sock:
                        sock.settimeout(10); sock.sendall(b'\x05\x01\x00')
                        if exact(sock,2)!=b'\x05\x00': raise RuntimeError('SOCKS auth failed')
                        sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
                        reply=exact(sock,10)
                        if reply[:2]==b'\x05\x00':
                            sock.sendall(b'rejected'); sock.shutdown(socket.SHUT_WR)
                            if sock.recv(1): raise RuntimeError(f'{mode} received data')
                    try: peer,_=origin.accept()
                    except TimeoutError: pass
                    else: peer.close(); raise RuntimeError(f'{mode} connected to origin')
                finally:
                    invalid_box.terminate(); invalid_box.wait(timeout=5)
            origin.settimeout(10)
            with socket.create_connection(('127.0.0.1',port),timeout=10) as stalled:
                stalled.settimeout(10); stalled.sendall(b'\x05\x01\x00')
                if exact(stalled,2)!=b'\x05\x00': raise RuntimeError('stalled SOCKS auth failed')
                stalled.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
                if exact(stalled,10)[:2]!=b'\x05\x00': raise RuntimeError('stalled SOCKS connect failed')
                stalled.sendall(b'hold'); peer,_=origin.accept(); peer.settimeout(10)
                try:
                    if exact(peer,4)!=b'hold': raise RuntimeError('stalled origin data mismatch')
                    nexus.terminate(); nexus.wait(timeout=5)
                    if nexus.returncode!=0: raise RuntimeError(f'Nexus shutdown failed: {nexus.returncode}')
                    def closed(sock):
                        try: return not sock.recv(1)
                        except ConnectionResetError: return True
                    if not closed(stalled) or not closed(peer): raise RuntimeError('stalled sockets survived shutdown')
                finally: peer.close()
    finally:
        origin.close(); box.terminate()
        if nexus.poll() is None: nexus.terminate()
        box.wait(timeout=5); nexus.wait(timeout=5)
print(f"Vision TLS inbound concurrent sessions passed (server={'sing-box' if control else 'Nexus'}, client={'Nexus' if nexus_client else 'sing-box'}, deferred={deferred})")
