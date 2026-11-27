"""Production Reality fallback failures, partial input, backpressure and stop."""
from test_paths import require_nexus
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
def listener(port=0):
    sock=socket.socket(); sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.bind(('127.0.0.1',port)); sock.listen(8); sock.settimeout(12); return sock
def read_all(sock):
    data=bytearray()
    while part:=sock.recv(16384): data.extend(part)
    return bytes(data)
def closed(sock):
    try: return not sock.recv(1)
    except ConnectionResetError: return True
with tempfile.TemporaryDirectory(prefix='nexus-reality-faults-') as directory:
    path=pathlib.Path(directory); (path/'secret').write_text('25'+'00'*31+'\n'); (path/'secret').chmod(0o600)
    (path/'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n'); (path/'uuid').chmod(0o600)
    with listener() as reserve: front=reserve.getsockname()[1]
    cover=listener(); cover_port=cover.getsockname()[1]
    (path/'server.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbound "edge" type="vless" {{ listen host="127.0.0.1" port={front}; authentication {{ user "test" uuid-file="{path/'uuid'}"; }}; tls {{ reality {{ private-key-file "{path/'secret'}"; server-name "localhost"; short-id ""; fallback host="localhost" port={cover_port}; }}; }}; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
    server=subprocess.Popen([require_nexus(),'run','--config',path/'server.kdl'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    def connect():
        deadline=time.monotonic()+8
        while True:
            if server.poll() is not None: raise RuntimeError(f'server exited: {server.stderr.read()!r}')
            try:
                sock=socket.create_connection(('127.0.0.1',front),timeout=1); sock.settimeout(12); return sock
            except ConnectionRefusedError:
                if time.monotonic()>deadline: raise
                time.sleep(.05)
    try:
        # EOF in a partial TLS record must reach cover byte-for-byte and permit
        # cover to send a response after observing the client's half-close.
        with connect() as client:
            data=b'\x16\x03\x01\x00\x80partial hello'
            client.sendall(data); client.shutdown(socket.SHUT_WR)
            peer,_=cover.accept(); peer.settimeout(10)
            with peer:
                if read_all(peer)!=data: raise RuntimeError('partial hello changed')
                peer.sendall(b'after EOF'); peer.shutdown(socket.SHUT_WR)
                if read_all(client)!=b'after EOF': raise RuntimeError('cover EOF response changed')
        # A refused cover connection closes only the failed client. Reopening
        # the same port must allow the next session to recover.
        cover.close()
        with connect() as client:
            client.sendall(b'bad TLS'); client.shutdown(socket.SHUT_WR)
            if not closed(client): raise RuntimeError('unavailable cover left client open')
        cover=listener(cover_port)
        with connect() as client:
            client.sendall(b'bad TLS'); client.shutdown(socket.SHUT_WR)
            peer,_=cover.accept(); peer.settimeout(10)
            with peer:
                if read_all(peer)!=b'bad TLS': raise RuntimeError('cover did not recover')
                peer.shutdown(socket.SHUT_WR)
                if not closed(client): raise RuntimeError('recovered session did not close')
        # Leave probe pending. The handshake deadline closes it without opening
        # a cover connection, and another session remains usable afterward.
        with connect() as slow:
            slow.sendall(b'\x16\x03'); started=time.monotonic()
            if not closed(slow): raise RuntimeError('slow probe remained open')
            elapsed=time.monotonic()-started
            if elapsed<8 or elapsed>12: raise RuntimeError(f'probe deadline {elapsed:.2f}s')
        cover.settimeout(.2)
        try: unexpected,_=cover.accept()
        except TimeoutError: pass
        else: unexpected.close(); raise RuntimeError('timed-out probe dialed cover')
        cover.settimeout(10)
        with connect() as client:
            client.sendall(b'after deadline'); client.shutdown(socket.SHUT_WR)
            peer,_=cover.accept(); peer.settimeout(10)
            with peer:
                if read_all(peer)!=b'after deadline': raise RuntimeError('server did not recover after timeout')
                peer.shutdown(socket.SHUT_WR)
                if not closed(client): raise RuntimeError('recovery did not close')
        # Force a large forward write to block with an unread cover socket.
        # Stopping must cancel both sockets and drain the session promptly.
        client=connect(); client.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
        client.sendall(b'not TLS!')
        peer,_=cover.accept(); peer.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096); peer.settimeout(10)
        result=[]
        def writer():
            try: client.sendall(b'x'*(16*1024*1024)); result.append('completed')
            except OSError: result.append('closed')
        thread=threading.Thread(target=writer); thread.start()
        time.sleep(.2)
        if not thread.is_alive(): raise RuntimeError('expected backpressure was not reached')
        server.terminate(); server.wait(timeout=5); thread.join(5)
        if server.returncode or thread.is_alive() or result!=['closed']: raise RuntimeError(f'stop did not drain blocked writer: {result}')
        with client,peer:
            # Buffered data can precede EOF; drain it before asserting closure.
            peer.settimeout(5); read_all(peer)
            if not closed(client): raise RuntimeError('client survived stop')
    finally:
        cover.close()
        if server.poll() is None: server.terminate(); server.wait(timeout=5)
print('Reality partial probe, cover refusal/recovery, deadline and backpressure stop passed')
