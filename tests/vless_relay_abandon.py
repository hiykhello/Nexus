"""Drive the VLESS relay abandonment test through a real TLS client."""
from test_paths import require_fixture
import json
import pathlib
import socket
import subprocess
import tempfile
import time
ROOT=pathlib.Path(__file__).resolve().parents[1]
def exact(sock,n):
    result=bytearray()
    while len(result)<n:
        part=sock.recv(n-len(result))
        if not part: raise RuntimeError('unexpected EOF')
        result.extend(part)
    return bytes(result)
with tempfile.TemporaryDirectory(prefix='nexus-vless-abandon-') as directory:
    path=pathlib.Path(directory)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',path/'key','-out',path/'cert',
        '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    (path/'key').chmod(0o600); (path/'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n'); (path/'uuid').chmod(0o600)
    origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(1); origin.settimeout(10)
    server=subprocess.Popen([require_fixture('proxy-vless-relay-abandon-test'),path/'cert',path/'key',path/'uuid'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    box=None
    try:
        port=int(server.stdout.readline())
        with socket.socket() as reserve: reserve.bind(('127.0.0.1',0)); socks=reserve.getsockname()[1]
        config={'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':socks}],
            'outbounds':[{'type':'vless','server':'127.0.0.1','server_port':port,'uuid':'00010203-0405-0607-0809-0a0b0c0d0e0f',
                          'tls':{'enabled':True,'server_name':'localhost','certificate_path':str(path/'cert')}}]}
        (path/'box.json').write_text(json.dumps(config)); box=subprocess.Popen(['sing-box','run','-c',path/'box.json'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        deadline=time.monotonic()+5
        while True:
            try: client=socket.create_connection(('127.0.0.1',socks),timeout=1); break
            except ConnectionRefusedError:
                if box.poll() is not None or server.poll() is not None or time.monotonic()>deadline: raise RuntimeError('client startup failed')
                time.sleep(.05)
        with client:
            client.settimeout(10); client.sendall(b'\x05\x01\x00')
            if exact(client,2)!=b'\x05\x00': raise RuntimeError('SOCKS auth failed')
            client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
            if exact(client,10)[:2]!=b'\x05\x00': raise RuntimeError('SOCKS connect failed')
            peer,_=origin.accept()
            with peer:
                stdout,stderr=server.communicate(timeout=10)
                if server.returncode: raise RuntimeError(f'abandon failed: {server.returncode} {stdout!r} {stderr!r}')
                if 'both VLESS relay frames destroyed' not in stdout: raise RuntimeError('missing lifetime assertion')
    finally:
        origin.close()
        if box and box.poll() is None: box.terminate(); box.wait(timeout=5)
        if server.poll() is None: server.kill(); server.wait()
print('VLESS relay frames and profile abandonment passed')
