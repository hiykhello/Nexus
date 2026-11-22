"""Update local DNS while an earlier production query remains in flight."""
from test_paths import require_nexus
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
ROOT=pathlib.Path(__file__).resolve().parents[1]
if '--inside' not in sys.argv:
    subprocess.run(['unshare','-Urnm',sys.executable,__file__,'--inside'],check=True)
    print('local DNS snapshot reload and in-flight version isolation passed')
    sys.exit(0)
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['mount','--make-rprivate','/'],check=True)
def exact(sock,n):
    data=b''
    while len(data)<n:
        chunk=sock.recv(n-len(data))
        if not chunk: raise RuntimeError('unexpected EOF')
        data+=chunk
    return data
with tempfile.TemporaryDirectory(prefix='nexus-local-reload-') as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as old_dns, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as new_dns, socket.socket() as origin, socket.socket() as new_origin:
    path=pathlib.Path(directory)
    (path/'resolv').write_text('nameserver 127.0.0.2\noptions timeout:5 attempts:1\n')
    (path/'hosts').write_text('127.0.0.1 localhost\n')
    for source,dest in (('resolv','/etc/resolv.conf'),('hosts','/etc/hosts')): subprocess.run(['mount','--bind',path/source,dest],check=True)
    subprocess.run(['cc','-shared','-fPIC',ROOT/'tests/proxy_dns_system_guard.c','-o',path/'guard.so'],check=True)
    old_dns.bind(('127.0.0.2',53)); old_dns.settimeout(5)
    new_dns.bind(('127.0.0.3',53)); new_dns.settimeout(5)
    origin.bind(('127.0.0.1',0)); origin.listen(4); origin.settimeout(5)
    new_origin.bind(('127.0.0.2',origin.getsockname()[1])); new_origin.listen(4); new_origin.settimeout(5)
    with socket.socket() as reserve: reserve.bind(('127.0.0.1',0)); port=reserve.getsockname()[1]
    (path/'config').write_text(f'''schema-version 1
role "client"
workers 2
dns {{ server "local" type="local"; strategy "ipv4_only"; }}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    env=os.environ.copy(); env['LD_PRELOAD']=str(path/'guard.so')
    proc=subprocess.Popen([require_nexus(),'run','--config',path/'config'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    def connect():
        deadline=time.monotonic()+8
        while True:
            if proc.poll() is not None: raise RuntimeError(proc.stderr.read())
            try: return socket.create_connection(('127.0.0.1',port),timeout=3)
            except ConnectionRefusedError:
                if time.monotonic()>deadline: raise
                time.sleep(.02)
    def request(client,name):
        client.settimeout(5); client.sendall(b'\x05\x01\x00'); assert exact(client,2)==b'\x05\x00'
        name=name.encode(); client.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+origin.getsockname()[1].to_bytes(2,'big'))
    def answer(dns,query,peer,name,address=b'\x7f\x00\x00\x01'):
        if query[12:-4]!=name or query[-4:]!=b'\x00\x01\x00\x01': raise RuntimeError(f'wrong DNS question: {query!r}')
        dns.sendto(query[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+query[12:]+b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'+address,peer)
    try:
        with connect() as first:
            request(first,'shared.test'); old_query,old_peer=old_dns.recvfrom(4096)
            (path/'resolv').write_text('nameserver 127.0.0.3\noptions timeout:5 attempts:1\n')
            time.sleep(1.6)
            with connect() as second:
                request(second,'shared.test'); new_query,new_peer=new_dns.recvfrom(4096)
                answer(new_dns,new_query,new_peer,b'\x06shared\x04test\x00',b'\x7f\x00\x00\x02')
                if exact(second,10)[:2]!=b'\x05\x00': raise RuntimeError('new snapshot failed')
                with new_origin.accept()[0] as peer:
                    second.sendall(b'new'); assert exact(peer,3)==b'new'
            answer(old_dns,old_query,old_peer,b'\x06shared\x04test\x00')
            if exact(first,10)[:2]!=b'\x05\x00': raise RuntimeError('in-flight old snapshot failed')
            with origin.accept()[0] as peer:
                first.sendall(b'old'); assert exact(peer,3)==b'old'
        # A late answer from the old view must not replace the new view's cache.
        with connect() as client:
            request(client,'shared.test')
            if exact(client,10)[:2]!=b'\x05\x00': raise RuntimeError('new snapshot cache failed')
            with new_origin.accept()[0] as peer:
                client.sendall(b'cached'); assert exact(peer,6)==b'cached'
        new_dns.settimeout(.3)
        try:
            unexpected,_=new_dns.recvfrom(4096)
            raise RuntimeError(f'new snapshot missed its cache: {unexpected!r}')
        except TimeoutError: pass
        (path/'hosts').write_text('127.0.0.1 fresh.test\n')
        time.sleep(1.6)
        with connect() as client:
            request(client,'fresh.test')
            if exact(client,10)[:2]!=b'\x05\x00': raise RuntimeError('updated hosts failed')
            with origin.accept()[0] as peer:
                client.sendall(b'host'); assert exact(peer,4)==b'host'
        (path/'resolv').write_text('nameserver invalid\n')
        time.sleep(1.6)
        with connect() as client:
            request(client,'fresh.test')
            if exact(client,10)[1]==0: raise RuntimeError('invalid config retained stale hosts')
        (path/'resolv').write_text('nameserver 127.0.0.3\noptions timeout:5 attempts:1\n')
        time.sleep(1.6)
        with connect() as client:
            request(client,'fresh.test')
            if exact(client,10)[:2]!=b'\x05\x00': raise RuntimeError('snapshot failed to recover')
            origin.accept()[0].close()
        proc.terminate(); proc.wait(timeout=5)
    finally:
        if proc.poll() is None: proc.terminate(); proc.wait(timeout=5)
        errors=proc.stderr.read(); proc.stderr.close()
        if proc.returncode or b'unexpected-system-resolver' in errors: raise RuntimeError(f'proxy={proc.returncode}: {errors!r}')
