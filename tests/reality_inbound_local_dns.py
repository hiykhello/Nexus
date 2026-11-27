"""Reality cover uses asynchronous local DNS without getaddrinfo (Linux)."""
from test_paths import require_nexus
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
if '--inside' not in sys.argv:
    subprocess.run(['unshare','-Urnm',sys.executable,__file__,'--inside'],check=True)
    print('Reality local DNS snapshot, UDP resolution and cancellation passed without getaddrinfo')
    sys.exit(0)
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['mount','--make-rprivate','/'],check=True)
with tempfile.TemporaryDirectory(prefix='nexus-local-reality-') as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket() as cover:
    path=pathlib.Path(directory)
    (path/'resolv').write_text('nameserver 127.0.0.2\noptions timeout:2 attempts:1\nsearch .\n')
    (path/'hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
    subprocess.run(['mount','--bind',path/'resolv','/etc/resolv.conf'],check=True)
    subprocess.run(['mount','--bind',path/'hosts','/etc/hosts'],check=True)
    subprocess.run(['cc','-shared','-fPIC',ROOT/'tests/proxy_dns_system_guard.c','-o',path/'guard.so'],check=True)
    dns.bind(('127.0.0.2',53)); dns.settimeout(5)
    cover.bind(('127.0.0.1',0)); cover.listen(2); cover.settimeout(5)
    with socket.socket() as reserve: reserve.bind(('127.0.0.1',0)); front=reserve.getsockname()[1]
    (path/'secret').write_text('25'+'00'*31+'\n'); (path/'secret').chmod(0o600)
    (path/'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n'); (path/'uuid').chmod(0o600)
    (path/'server.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbound "edge" type="vless" {{ listen host="127.0.0.1" port={front}; authentication {{ user "test" uuid-file="{path/'uuid'}"; }}; tls {{ reality {{ private-key-file "{path/'secret'}"; server-name "localhost"; short-id ""; fallback host="cover.test" port={cover.getsockname()[1]}; }}; }}; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
    env=os.environ.copy(); env['LD_PRELOAD']=str(path/'guard.so')
    server=subprocess.Popen([require_nexus(),'run','--config',path/'server.kdl'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    def connect():
        limit=time.monotonic()+8
        while True:
            if server.poll() is not None: raise RuntimeError(server.stderr.read())
            try:
                client=socket.create_connection(('127.0.0.1',front),timeout=1); client.settimeout(5); return client
            except ConnectionRefusedError:
                if time.monotonic()>limit: raise
                time.sleep(.02)
    def query():
        packet,peer=dns.recvfrom(4096)
        if packet[12:-4]!=b'\x05cover\x04test\x00': raise RuntimeError(f'wrong query: {packet!r}')
        return packet,peer
    def answer(packet,peer):
        kind=int.from_bytes(packet[-4:-2],'big')
        payload=b'\x7f\x00\x00\x01' if kind==1 else bytes.fromhex('00000000000000000000000000000001') if kind==28 else None
        if payload is None: raise RuntimeError('unexpected query type')
        dns.sendto(packet[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+packet[12:]+b'\xc0\x0c'+kind.to_bytes(2,'big')+b'\x00\x01\x00\x00\x00\x3c'+len(payload).to_bytes(2,'big')+payload,peer)
    try:
        with connect() as client:
            client.sendall(b'not TLS!')
            for _ in range(2): answer(*query())
            peer,_=cover.accept(); peer.settimeout(5)
            with peer:
                if peer.recv(8)!=b'not TLS!': raise RuntimeError('wrong fallback payload')
                peer.sendall(b'ok')
                if client.recv(2)!=b'ok': raise RuntimeError('wrong fallback response')
        with connect() as client:
            client.sendall(b'not TLS!'); query()
            started=time.monotonic(); server.terminate(); server.wait(timeout=5)
            if server.returncode or time.monotonic()-started>2: raise RuntimeError('pending local DNS was not canceled')
            try: remaining=client.recv(1)
            except ConnectionResetError: remaining=b''
            if remaining: raise RuntimeError('client survived server stop')
    finally:
        if server.poll() is None: server.terminate(); server.wait(timeout=5)
        diagnostics=server.stderr.read(); server.stderr.close()
        if server.returncode or b'unexpected-system-resolver' in diagnostics: raise RuntimeError(f'server={server.returncode}: {diagnostics!r}')
