"""Production Reality/VLESS inbound with pinned sing-box and a TLS cover."""
from test_paths import require_nexus, require_fixture
import base64
import concurrent.futures
import json
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
vision='--vision' in sys.argv[1:]
xray='--xray' in sys.argv[1:]
stop_auth='--stop-auth' in sys.argv[1:]
generated='--generated' in sys.argv[1:]
REVISION='824dbcfb4dd0a95921840b1737b950cde590241e'
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
def wait_port(port,process):
    deadline=time.monotonic()+10
    while True:
        if process.poll() is not None: raise RuntimeError(f'process exited: {process.stderr.read()!r}')
        try: sock=socket.create_connection(('127.0.0.1',port),timeout=1); sock.close(); return
        except ConnectionRefusedError:
            if time.monotonic()>deadline: raise
            time.sleep(.05)
with tempfile.TemporaryDirectory(prefix='nexus-reality-inbound-') as directory:
    path=pathlib.Path(directory)
    def run(*args): subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    run('openssl','genpkey','-algorithm','ED25519','-out',str(path/'key.pem'))
    run('openssl','pkey','-in',str(path/'key.pem'),'-outform','DER','-out',str(path/'key.der'))
    run('openssl','req','-new','-x509','-key',str(path/'key.pem'),'-out',str(path/'cert.der'),'-outform','DER','-subj','/CN=localhost','-days','1')
    run('openssl','req','-new','-x509','-key',str(path/'key.pem'),'-out',str(path/'cert.pem'),'-subj','/CN=localhost','-days','1')
    (path/'key.der').chmod(0o600); (path/'secret').write_text('25'+'00'*31+'\n'); (path/'secret').chmod(0o600)
    (path/'x.der').write_bytes(bytes.fromhex('302e020100300506032b656e04220420'+'25'+'00'*31))
    public=subprocess.run(['openssl','pkey','-inform','DER','-in',path/'x.der','-pubout','-outform','DER'],check=True,capture_output=True).stdout[-32:]
    public64=base64.urlsafe_b64encode(public).decode().rstrip('=')
    uuid=path/'uuid'; uuid.write_text('00010203-0405-0607-0809-0a0b0c0d0e0f'); uuid.chmod(0o600)
    front,socks=free_port(),free_port()
    flow='flow "xtls-rprx-vision";' if vision else ''
    credentials='' if generated else f'certificate-file "{path/"cert.der"}"; signing-key-file "{path/"key.der"}";'
    cover=socket.socket(); cover.bind(('127.0.0.1',0)); cover.listen(8); cover.settimeout(10)
    origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(8); origin.settimeout(12)
    (path/'nexus.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbound "edge" type="vless" {{ listen host="127.0.0.1" port={front}; {flow} authentication {{ user "test" uuid-file="{uuid}"; }}; tls {{ reality {{ private-key-file "{path/'secret'}"; {credentials} server-name "localhost"; short-id "0102030405060708"; fallback host="localhost" port={cover.getsockname()[1]}; }}; }}; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
    cfg={'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':socks}],
         'outbounds':[{'type':'vless','server':'127.0.0.1','server_port':front,'uuid':'00010203-0405-0607-0809-0a0b0c0d0e0f',
            'tls':{'enabled':True,'server_name':'localhost','utls':{'enabled':True,'fingerprint':'chrome'},'reality':{'enabled':True,'public_key':public64,'short_id':'0102030405060708'}}}]}
    if vision: cfg['outbounds'][0]['flow']='xtls-rprx-vision'
    if xray:
        binary=pathlib.Path('/tmp/nexus-xray-bin/main')
        version=subprocess.run(['go','version','-m',binary],check=True,capture_output=True,text=True).stdout
        if '\tmod\tgithub.com/xtls/xray-core\tv1.260327.0\th1:g4TzxMwyPrxslZh6uD+FiG3lXKTrnNO+b4ky2OhogHE=' not in version: raise RuntimeError('unexpected Xray version')
        user={'id':'00010203-0405-0607-0809-0a0b0c0d0e0f','encryption':'none'}
        if vision: user['flow']='xtls-rprx-vision'
        cfg={'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':socks,'protocol':'socks','settings':{'auth':'noauth'}}],
             'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':front,'users':[user]}]},
             'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':'localhost','fingerprint':'chrome','password':public64,'shortId':'0102030405060708'}}}]}
    (path/'box.json').write_text(json.dumps(cfg))
    if not xray: subprocess.run(['sing-box','check','-c',path/'box.json'],check=True)
    nexus=subprocess.Popen([require_nexus(),'run','--config',path/'nexus.kdl'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    box=subprocess.Popen(([binary,'run','-config',path/'box.json'] if xray else ['sing-box','run','-c',path/'box.json']),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    errors=[]
    def serve_origin():
        threads=[]
        def one(conn):
            try:
                with conn:
                    conn.settimeout(10)
                    while part:=conn.recv(16384): conn.sendall(part)
                    conn.shutdown(socket.SHUT_WR)
            except BaseException as exc: errors.append(exc)
        try:
            for _ in range(4):
                conn,_=origin.accept(); thread=threading.Thread(target=one,args=(conn,)); thread.start(); threads.append(thread)
            for thread in threads: thread.join(12)
            if any(thread.is_alive() for thread in threads): raise RuntimeError('origin hung')
        except BaseException as exc: errors.append(exc)
    worker=threading.Thread(target=serve_origin,daemon=True); worker.start()
    try:
        wait_port(socks,box); wait_port(front,nexus)
        def client(index):
            with socket.create_connection(('127.0.0.1',socks),timeout=10) as conn:
                conn.settimeout(10); conn.sendall(b'\x05\x01\x00')
                if exact(conn,2)!=b'\x05\x00': raise RuntimeError('SOCKS authentication')
                conn.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
                if exact(conn,10)[:2]!=b'\x05\x00': raise RuntimeError('SOCKS connect')
                payload=(f'production Reality {index}:'.encode()*1200); conn.sendall(payload)
                if exact(conn,len(payload))!=payload: raise RuntimeError('data mismatch')
                conn.shutdown(socket.SHUT_WR)
                if conn.recv(1): raise RuntimeError('unexpected trailing data')
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(client,range(4)))
        worker.join(12)
        if worker.is_alive() or errors: raise RuntimeError(f'origin: {errors}')
        # The readiness probe is an empty fallback connection; skip it.
        cover_conn,_=cover.accept(); cover_conn.close()
        def cover_server():
            try:
                conn,_=cover.accept(); conn.settimeout(10)
                ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(path/'cert.pem',path/'key.pem')
                with ctx.wrap_socket(conn,server_side=True) as tls:
                    if exact(tls,13)!=b'cover request': raise RuntimeError('cover request mismatch')
                    tls.sendall(b'cover reply'); raw=tls.unwrap(); raw.shutdown(socket.SHUT_WR); raw.close()
            except BaseException as exc: errors.append(exc)
        worker=threading.Thread(target=cover_server,daemon=True); worker.start()
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with ctx.wrap_socket(socket.create_connection(('127.0.0.1',front)),server_hostname='localhost') as tls:
            tls.settimeout(10); tls.sendall(b'cover request')
            if exact(tls,11)!=b'cover reply': raise RuntimeError('cover response mismatch')
            raw=tls.unwrap(); raw.shutdown(socket.SHUT_WR); raw.close()
        worker.join(12)
        if worker.is_alive() or errors: raise RuntimeError(f'cover: {errors}')
        # An authenticated-looking ClientHello with the wrong short ID must go
        # to cover, and must never establish a VLESS session.
        invalid=subprocess.Popen([require_fixture('reality-client-fixture'),str(front),public.hex(),'localhost','12345','0102030405060709'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            rejected,_=cover.accept(); rejected.settimeout(10)
            with rejected:
                header=exact(rejected,5)
                if header[0]!=22: raise RuntimeError('wrong ID did not fall back with ClientHello')
                exact(rejected,int.from_bytes(header[3:5],'big'))
            if invalid.wait(timeout=10)==0: raise RuntimeError('wrong short ID accepted')
        finally:
            if invalid.poll() is None: invalid.kill(); invalid.wait()
        if stop_auth:
            # Keep an authenticated VLESS stream and its direct destination
            # active while stopping the server, then verify both ends close.
            with socket.create_connection(('127.0.0.1',socks),timeout=10) as stalled:
                stalled.settimeout(10); stalled.sendall(b'\x05\x01\x00')
                if exact(stalled,2)!=b'\x05\x00': raise RuntimeError('SOCKS auth failed')
                stalled.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
                if exact(stalled,10)[:2]!=b'\x05\x00': raise RuntimeError('SOCKS connect failed')
                stalled.sendall(b'active'); peer,_=origin.accept(); peer.settimeout(10)
                with peer:
                    if exact(peer,6)!=b'active': raise RuntimeError('active stream data mismatch')
                    nexus.terminate(); nexus.wait(timeout=5)
                    if nexus.returncode: raise RuntimeError(f'Nexus stop failed: {nexus.returncode}')
                    def closed(sock):
                        try: return not sock.recv(1)
                        except ConnectionResetError: return True
                    if not closed(stalled) or not closed(peer): raise RuntimeError('authenticated sockets survived stop')
        else:
            # Stop with an active fallback and confirm both sockets close.
            stalled=socket.create_connection(('127.0.0.1',front),timeout=10); stalled.settimeout(10)
            stalled.sendall(b'not TLS data')
            peer,_=cover.accept(); peer.settimeout(10)
            with stalled, peer:
                if exact(peer,12)!=b'not TLS data': raise RuntimeError('stalled fallback data mismatch')
                nexus.terminate(); nexus.wait(timeout=5)
                if nexus.returncode: raise RuntimeError(f'Nexus stop failed: {nexus.returncode}')
                def closed(sock):
                    try: return not sock.recv(1)
                    except ConnectionResetError: return True
                if not closed(stalled) or not closed(peer): raise RuntimeError('fallback sockets survived stop')
    finally:
        origin.close(); cover.close()
        for process in (box,nexus):
            if process.poll() is None: process.terminate()
        for process in (box,nexus): process.wait(timeout=5)
print(f'Production Reality inbound: concurrent VLESS, TLS fallback passed (xray={xray}, vision={vision}, stop_auth={stop_auth}, generated={generated})')
