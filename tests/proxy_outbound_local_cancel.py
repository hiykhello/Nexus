"""Cancel local DNS for VLESS and SS tunnel servers without libc resolution."""
from test_paths import require_nexus
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
    print('VLESS and SS outbound local DNS cancellation passed without getaddrinfo')
    sys.exit(0)
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['mount','--make-rprivate','/'],check=True)
with tempfile.TemporaryDirectory(prefix='nexus-outbound-local-') as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
    path=pathlib.Path(directory)
    (path/'resolv').write_text('nameserver 127.0.0.2\noptions timeout:5 attempts:1\nsearch .\n')
    (path/'hosts').write_text('127.0.0.1 localhost\n')
    for source,dest in (('resolv','/etc/resolv.conf'),('hosts','/etc/hosts')): subprocess.run(['mount','--bind',path/source,dest],check=True)
    subprocess.run(['cc','-shared','-fPIC',ROOT/'tests/proxy_dns_system_guard.c','-o',path/'guard.so'],check=True)
    (path/'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n'); (path/'uuid').chmod(0o600)
    (path/'key').write_text(base64.b64encode(bytes(range(16))).decode()+'\n'); (path/'key').chmod(0o600)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',path/'cert.key','-out',path/'cert.pem','-subj','/CN=example.test','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    dns.bind(('127.0.0.2',53)); dns.settimeout(5)
    for protocol in ('vless','shadowsocks'):
        with socket.socket() as reserve: reserve.bind(('127.0.0.1',0)); front=reserve.getsockname()[1]
        if protocol=='vless':
            edge=f'outbound "edge" type="vless" {{ server host="edge.test" port=8443; authentication {{ uuid-file "{path/"uuid"}"; }}; tls {{ server-name "example.test"; ca-file "{path/"cert.pem"}"; verify #true; }}; }}'
        else:
            edge=f'outbound "edge" type="shadowsocks" {{ server host="edge.test" port=8443; method "2022-blake3-aes-128-gcm"; key-file "{path/"key"}"; }}'
        (path/'config').write_text(f'''schema-version 1\nrole "client"\nworkers 1\ninbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}\n{edge}\noutbound "direct" type="direct"\nrouting {{ final "edge"; }}\n''')
        env=os.environ.copy(); env['LD_PRELOAD']=str(path/'guard.so')
        proc=subprocess.Popen([require_nexus(),'run','--config',path/'config'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+8
            while True:
                if proc.poll() is not None: raise RuntimeError(proc.stderr.read())
                try: client=socket.create_connection(('127.0.0.1',front),timeout=2); break
                except ConnectionRefusedError:
                    if time.monotonic()>deadline: raise
                    time.sleep(.02)
            with client:
                client.settimeout(5); client.sendall(b'\x05\x01\x00')
                if client.recv(2)!=b'\x05\x00': raise RuntimeError('greeting')
                client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50')
                query,_=dns.recvfrom(4096)
                if query[12:-4]!=b'\x04edge\x04test\x00': raise RuntimeError('wrong DNS name')
                start=time.monotonic(); proc.terminate(); proc.wait(timeout=4)
                if time.monotonic()-start>2: raise RuntimeError('pending outbound DNS did not cancel')
        finally:
            if proc.poll() is None: proc.terminate(); proc.wait(timeout=5)
            diagnostics=proc.stderr.read(); proc.stderr.close()
            if proc.returncode or b'unexpected-system-resolver' in diagnostics: raise RuntimeError(f'{protocol}: {proc.returncode} {diagnostics!r}')
