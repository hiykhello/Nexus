"""Production SS UDP local DNS cancellation with isolated resolv.conf."""
from test_paths import require_nexus, require_fixture
import base64
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
    print('SS UDP local DNS query and stop passed without getaddrinfo')
    sys.exit(0)
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['mount','--make-rprivate','/'],check=True)
with tempfile.TemporaryDirectory(prefix='nexus-ss-udp-local-') as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as new_dns:
    path=pathlib.Path(directory)
    (path/'resolv').write_text('nameserver 127.0.0.2\noptions timeout:5 attempts:1\nsearch .\n')
    (path/'hosts').write_text('127.0.0.1 localhost\n')
    for source,dest in (('resolv','/etc/resolv.conf'),('hosts','/etc/hosts')): subprocess.run(['mount','--bind',path/source,dest],check=True)
    subprocess.run(['cc','-shared','-fPIC',ROOT/'tests/proxy_dns_system_guard.c','-o',path/'guard.so'],check=True)
    (path/'key').write_text(base64.b64encode(bytes(range(16))).decode()+'\n'); (path/'key').chmod(0o600)
    dns.bind(('127.0.0.2',53)); dns.settimeout(5)
    new_dns.bind(('127.0.0.3',53)); new_dns.settimeout(5)
    for explicit in (False,True):
        (path/'resolv').write_text('nameserver 127.0.0.2\noptions timeout:5 attempts:1\nsearch .\n')
        with socket.socket() as reserve: reserve.bind(('127.0.0.1',0)); port=reserve.getsockname()[1]
        cfg='dns { server "local" type="local"; }' if explicit else ''
        (path/'config').write_text(f'''schema-version 1\nrole "server"\nworkers 1\n{cfg}\ninbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{path/'key'}"; }}\noutbound "direct" type="direct"\nrouting {{ final "direct"; }}\n''')
        env=os.environ.copy(); env['LD_PRELOAD']=str(path/'guard.so')
        proc=subprocess.Popen([require_nexus(),'run','--config',path/'config'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+8
            while True:
                if proc.poll() is not None: raise RuntimeError(proc.stderr.read())
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                except ConnectionRefusedError:
                    if time.monotonic()>deadline: raise
                    time.sleep(.02)
            subprocess.run([require_fixture('nexus-shadowsocks-udp-rebind-test'),str(port),'16','system-stall'],check=True,timeout=3)
            query,_=dns.recvfrom(4096)
            if query[12:-4]!=b'\x0bnexus-delay\x04test\x00': raise RuntimeError(f'wrong query {query!r}')
            (path/'resolv').write_text('nameserver 127.0.0.3\noptions timeout:5 attempts:1\nsearch .\n')
            time.sleep(1.6)
            subprocess.run([require_fixture('nexus-shadowsocks-udp-rebind-test'),str(port),'16','system-stall-next'],check=True,timeout=3)
            query,_=new_dns.recvfrom(4096)
            if query[12:-4]!=b'\x0bnexus-delay\x04test\x00': raise RuntimeError(f'wrong reloaded query {query!r}')
            start=time.monotonic(); proc.terminate(); proc.wait(timeout=4)
            if time.monotonic()-start>2: raise RuntimeError('pending UDP DNS did not cancel')
        finally:
            if proc.poll() is None: proc.terminate(); proc.wait(timeout=5)
            diagnostics=proc.stderr.read(); proc.stderr.close()
            if proc.returncode or b'unexpected-system-resolver' in diagnostics: raise RuntimeError(f'server={proc.returncode}: {diagnostics!r}')
