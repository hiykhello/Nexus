#!/usr/bin/env python3
"""Exercise configured production Trojan against a custom-extension OpenSSL TLS peer."""
import argparse
import pathlib
import select
import socket
import subprocess
import tempfile
import threading
from detour_network import socks
from dns_rule_support import exact, free_port, nexus_process

parser=argparse.ArgumentParser();parser.add_argument('nexus',type=pathlib.Path);parser.add_argument('peer',type=pathlib.Path)
args=parser.parse_args();nexus=args.nexus.resolve();peer=args.peer.resolve()
with tempfile.TemporaryDirectory(prefix='nexus-record-limit-proxy-') as directory:
    root=pathlib.Path(directory);cert=root/'cert.pem';key=root/'key.pem';password=root/'password'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),
                    '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],check=True,capture_output=True)
    password.write_text('nexus-test-password\n');password.chmod(0o600)
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(10)
    front=free_port();config=root/'config.kdl'
    config.write_text(f'''schema-version 1
role "client"
workers 1
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="trojan" {{ server host="127.0.0.1" port={listener.getsockname()[1]};
 authentication {{ password-file "{password}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; fingerprint "tls13-randomized"; record-size-limit 1024; verify #true; }} }}
routing {{ final "edge"; }}
''')
    errors=[];records=[];observed_offer=[]
    def serve_checked():
        child=None
        try:
            source,_=listener.accept()
            relay,server=socket.socketpair()
            with source,relay,server:
                child=subprocess.Popen([str(peer),str(cert),str(key),'proxy'],stdin=server,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                server.close();source.setblocking(False);relay.setblocking(False)
                active={source:relay,relay:source};pending=bytearray()
                while active:
                    ready,_,_=select.select(list(active),[],[],10)
                    if not ready:raise TimeoutError('TLS relay stalled')
                    for sock in ready:
                        data=sock.recv(65536)
                        if not data:
                            try:active[sock].shutdown(socket.SHUT_WR)
                            except OSError:pass
                            del active[sock];continue
                        if sock is source:
                            pending.extend(data)
                            while len(pending)>=5:
                                size=5+int.from_bytes(pending[3:5],'big')
                                if len(pending)<size:break
                                records.append((pending[0],size-5));del pending[:size]
                        view=memoryview(data);dest=active[sock]
                        while view:
                            if not select.select([], [dest], [], 10)[1]:raise TimeoutError('TLS relay write stalled')
                            view=view[dest.send(view):]
                if pending:raise RuntimeError('truncated client TLS record')
                _,err=child.communicate(timeout=15)
                if child.returncode:errors.append(f'OpenSSL peer exit {child.returncode}: {err!r}')
        except Exception as exc:
            errors.append(repr(exc))
            if child and child.poll() is None:child.kill();child.communicate()
    worker=threading.Thread(target=serve_checked,daemon=True);worker.start()
    try:
        with nexus_process(str(nexus),str(config)):
            with socks(front,1,('127.0.0.1',12345))[0] as client:
                client.settimeout(10);payload=bytes(range(256))*8;client.sendall(payload)
                if exact(client,len(payload))!=payload:raise RuntimeError('Trojan payload mismatch')
                client.shutdown(socket.SHUT_WR)
                if client.recv(1):raise RuntimeError('unexpected trailing data')
        worker.join(15)
        if worker.is_alive() or errors:raise RuntimeError(f'peer errors: {errors}')
        encrypted=[size for kind,size in records if kind==23]
        if not encrypted or max(encrypted)>512+16:
            raise RuntimeError(f'client exceeded peer TLSInnerPlaintext limit: {records}')
        if len(encrypted)<5:raise RuntimeError(f'expected fragmented client records: {records}')
    finally:
        listener.close();worker.join(1)
    print(f'production Trojan: peer limit512, {len(encrypted)} client ciphertext records <=528 bytes, target 127.0.0.1:12345, 2048 bytes each direction and close passed',flush=True)
