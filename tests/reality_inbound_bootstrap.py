"""Reality cover resolution through configured DNS, including cancellation."""
from test_paths import require_nexus
import pathlib
import socket
import subprocess
import tempfile
import time
ROOT=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='nexus-reality-bootstrap-') as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket() as cover:
    path=pathlib.Path(directory); dns.bind(('127.0.0.1',0)); dns.settimeout(8)
    cover.bind(('127.0.0.1',0)); cover.listen(4); cover.settimeout(8)
    with socket.socket() as reserve: reserve.bind(('127.0.0.1',0)); front=reserve.getsockname()[1]
    (path/'secret').write_text('25'+'00'*31+'\n'); (path/'secret').chmod(0o600)
    (path/'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n'); (path/'uuid').chmod(0o600)
    (path/'server.kdl').write_text(f'''schema-version 1
role "server"
workers 2
dns {{ server "bootstrap" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; disable-cache #true; }}
inbound "edge" type="vless" {{ listen host="127.0.0.1" port={front}; authentication {{ user "test" uuid-file="{path/'uuid'}"; }}; tls {{ reality {{ private-key-file "{path/'secret'}"; server-name "localhost"; short-id ""; fallback host="cover.test" port={cover.getsockname()[1]}; fallback-resolver "bootstrap"; }}; }}; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    server=subprocess.Popen([require_nexus(),'run','--config',path/'server.kdl'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    def connect():
        deadline=time.monotonic()+8
        while True:
            if server.poll() is not None: raise RuntimeError(f'server exited {server.stderr.read()!r}')
            try: sock=socket.create_connection(('127.0.0.1',front),timeout=1); sock.settimeout(8); return sock
            except ConnectionRefusedError:
                if time.monotonic()>deadline: raise
                time.sleep(.05)
    def query():
        packet,peer=dns.recvfrom(4096)
        if packet[12:-4]!=b'\x05cover\x04test\x00' or packet[-4:]!=b'\x00\x01\x00\x01': raise RuntimeError(f'unexpected query {packet!r}')
        return packet,peer
    def closed(sock):
        try: return not sock.recv(1)
        except ConnectionResetError: return True
    try:
        with connect() as client:
            client.sendall(b'not TLS!'); packet,peer=query()
            dns.sendto(packet[:2]+b'\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00'+packet[12:],peer)
            if not closed(client): raise RuntimeError('DNS rejection did not close client')
        with connect() as client:
            client.settimeout(14)
            started=time.monotonic(); client.sendall(b'not TLS!'); query()
            if not closed(client) or time.monotonic()-started>12:
                raise RuntimeError('pending DNS did not expire within the handshake deadline')
        dns.setblocking(False)
        try:
            while True: dns.recvfrom(4096)
        except BlockingIOError: pass
        dns.settimeout(8)
        with connect() as client:
            client.sendall(b'not TLS!'); packet,peer=query()
            response=packet[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+packet[12:]+b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01'
            dns.sendto(response,peer)
            stream,_=cover.accept(); stream.settimeout(8)
            with stream:
                if stream.recv(8)!=b'not TLS!': raise RuntimeError('resolved cover payload mismatch')
                stream.sendall(b'ok');
                if client.recv(2)!=b'ok': raise RuntimeError('resolved cover response mismatch')
        with connect() as client:
            client.sendall(b'not TLS!'); query()
            started=time.monotonic(); server.terminate(); server.wait(timeout=5)
            if server.returncode or time.monotonic()-started>2 or not closed(client): raise RuntimeError('pending DNS did not cancel promptly')
    finally:
        if server.poll() is None: server.terminate(); server.wait(timeout=5)
print('Reality configured DNS rejection, timeout, recovery, and pending-query stop passed')
