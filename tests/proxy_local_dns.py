"""Exercise local DNS in SOCKS TCP with isolated system files and a resolver guard."""
from test_paths import require_nexus
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = (require_nexus()).resolve()
if '--inside' not in sys.argv:
    subprocess.run(['unshare', '-Urnm', sys.executable, __file__, '--inside'], check=True)
    print('SOCKS local DNS default and explicit resolver, hosts and cancellation passed')
    sys.exit(0)
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
subprocess.run(['mount', '--make-rprivate', '/'], check=True)

def exact(sock, n):
    out=b''
    while len(out)<n:
        chunk=sock.recv(n-len(out))
        if not chunk: raise RuntimeError('unexpected EOF')
        out+=chunk
    return out

with tempfile.TemporaryDirectory(prefix='nexus-local-socks-') as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket() as target, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp_target:
    path=pathlib.Path(directory)
    (path/'resolv').write_text('nameserver 127.0.0.2\noptions timeout:2 attempts:1\nsearch test\n')
    (path/'hosts').write_text('127.0.0.1 hosts.test\n')
    for source, dest in (('resolv','/etc/resolv.conf'),('hosts','/etc/hosts')):
        subprocess.run(['mount','--bind',path/source,dest],check=True)
    subprocess.run(['cc','-shared','-fPIC',ROOT/'tests/proxy_dns_system_guard.c','-o',path/'guard.so'],check=True)
    dns.bind(('127.0.0.2',53)); dns.settimeout(.1)
    target.bind(('127.0.0.1',0)); target.listen(4); target.settimeout(5)
    udp_target.bind(('127.0.0.1',0)); udp_target.settimeout(5)
    stop=threading.Event(); queries=[]; stalled=threading.Event(); errors=[]
    def serve_dns():
        try:
            while not stop.is_set():
                try: packet,peer=dns.recvfrom(4096)
                except TimeoutError: continue
                name=packet[12:-4]; kind=int.from_bytes(packet[-4:-2],'big'); queries.append((name,kind))
                if name==b'\x05stall\x04test\x00': stalled.set(); continue
                if name!=b'\x06target\x04test\x00' or kind not in (1,28): raise RuntimeError('unexpected DNS query')
                payload=b'\x7f\x00\x00\x01' if kind==1 else bytes.fromhex('00000000000000000000000000000001')
                dns.sendto(packet[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+packet[12:]+b'\xc0\x0c'+kind.to_bytes(2,'big')+b'\x00\x01\x00\x00\x00\x3c'+len(payload).to_bytes(2,'big')+payload,peer)
        except Exception as exc: errors.append(exc)
    thread=threading.Thread(target=serve_dns); thread.start()
    try:
        for explicit in (False, True):
            with socket.socket() as reserve: reserve.bind(('127.0.0.1',0)); front=reserve.getsockname()[1]
            dns_config='dns { server "local" type="local"; strategy "ipv4_only"; }' if explicit else ''
            (path/'server.kdl').write_text(f'''schema-version 1\nrole "server"\nworkers 1\n{dns_config}\ninbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}\noutbound "direct" type="direct"\nrouting {{ final "direct"; }}\n''')
            env=os.environ.copy(); env['LD_PRELOAD']=str(path/'guard.so')
            server=subprocess.Popen([BINARY,'run','--config',path/'server.kdl'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            def connect():
                deadline=time.monotonic()+8
                while True:
                    if server.poll() is not None: raise RuntimeError(server.stderr.read())
                    try: return socket.create_connection(('127.0.0.1',front),timeout=2)
                    except ConnectionRefusedError:
                        if time.monotonic()>deadline: raise
                        time.sleep(.02)
            def request(client,name):
                client.sendall(b'\x05\x01\x00')
                if exact(client,2)!=b'\x05\x00': raise RuntimeError('SOCKS greeting')
                raw=name.encode(); client.sendall(b'\x05\x01\x00\x03'+bytes([len(raw)])+raw+target.getsockname()[1].to_bytes(2,'big'))
            try:
                for name in ('hosts.test','target.test','target'):
                    before=len(queries)
                    with connect() as client:
                        request(client,name)
                        reply=exact(client,10)
                        if reply[:3]!=b'\x05\x00\x00': raise RuntimeError(f'SOCKS reply {reply!r}')
                        with target.accept()[0] as peer:
                            client.sendall(b'ping')
                            if exact(peer,4)!=b'ping': raise RuntimeError('data lost')
                            peer.sendall(b'pong')
                            if exact(client,4)!=b'pong': raise RuntimeError('response lost')
                    if name=='hosts.test' and len(queries)!=before: raise RuntimeError('hosts entry queried DNS')
                    if name=='target.test' and len(queries)==before: raise RuntimeError('missing DNS query')
                    if name=='target' and len(queries)!=before: raise RuntimeError('search result did not share the cached answer')
                with connect() as control, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                    client.bind(('127.0.0.1',0)); client.settimeout(5)
                    control.sendall(b'\x05\x01\x00')
                    if exact(control,2)!=b'\x05\x00': raise RuntimeError('UDP SOCKS greeting')
                    control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
                    reply=exact(control,10)
                    if reply[:4]!=b'\x05\x00\x00\x01': raise RuntimeError('UDP association failed')
                    relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],'big'))
                    name=b'target.test'; port=udp_target.getsockname()[1]
                    client.sendto(b'\x00\x00\x00\x03'+bytes([len(name)])+name+port.to_bytes(2,'big')+b'udp',relay)
                    data,peer=udp_target.recvfrom(1024)
                    if data!=b'udp': raise RuntimeError('UDP target received wrong payload')
                    udp_target.sendto(b'reply',peer)
                    data,_=client.recvfrom(1024)
                    if not data.endswith(b'reply'): raise RuntimeError('UDP reply lost')
                stalled.clear()
                with connect() as client:
                    request(client,'stall.test')
                    if not stalled.wait(3): raise RuntimeError('stalled DNS query not started')
                    started=time.monotonic(); server.terminate(); server.wait(timeout=4)
                    if time.monotonic()-started>2: raise RuntimeError('pending DNS did not cancel')
            finally:
                if server.poll() is None: server.terminate(); server.wait(timeout=5)
                diagnostics=server.stderr.read(); server.stderr.close()
                if server.returncode or b'unexpected-system-resolver' in diagnostics: raise RuntimeError(f'server={server.returncode}: {diagnostics!r}')
    finally:
        stop.set(); thread.join(timeout=2)
    if errors: raise errors[0]
