"""Exercise bounded Reality probing and exact fallback over TCP sockets."""
from test_paths import require_fixture
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading

root = pathlib.Path(__file__).resolve().parents[1]
fixture = require_fixture('reality-server-fixture')
def read_all(sock):
    data=bytearray()
    while part:=sock.recv(16384): data.extend(part)
    return bytes(data)
def tcp_pair():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); listener.listen(1)
        client=socket.create_connection(listener.getsockname()); server,_=listener.accept()
        return client,server
with tempfile.TemporaryDirectory(prefix='nexus-reality-fallback-') as directory:
    path=pathlib.Path(directory)
    (path/'secret').write_text('25'+'00'*31+'\n'); (path/'secret').chmod(0o600)
    def run(*args): subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    run('openssl','genpkey','-algorithm','ED25519','-out',str(path/'key.pem'))
    run('openssl','pkey','-in',str(path/'key.pem'),'-outform','DER','-out',str(path/'key.der'))
    run('openssl','req','-new','-x509','-key',str(path/'key.pem'),'-out',str(path/'cert.der'),'-outform','DER','-subj','/CN=localhost','-days','1')
    (path/'key.der').chmod(0o600)
    for payload in (b'not TLS\x00'+bytes(range(256))*300,
                    b'\x16\x03\x01\x40\x00'+bytes(range(256))*400):
        cover, cover_side=tcp_pair(); cover.settimeout(8)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); listener.listen(1)
            process=subprocess.Popen([fixture,str(listener.fileno()),path/'cert.der',path/'key.der',path/'secret',str(cover_side.fileno()),'64'],
                pass_fds=(listener.fileno(),cover_side.fileno()),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            cover_side.close()
            assert len(process.stdout.readline().strip())==64
            client=socket.create_connection(listener.getsockname()); client.settimeout(8)
            errors=[]
            def origin():
                try:
                    if read_all(cover)!=payload: raise AssertionError('fallback input mismatch')
                    cover.sendall(b'cover response'); cover.shutdown(socket.SHUT_WR)
                except BaseException as exc: errors.append(exc)
            thread=threading.Thread(target=origin); thread.start()
            try:
                client.sendall(payload); client.shutdown(socket.SHUT_WR)
                if read_all(client)!=b'cover response': raise AssertionError('fallback response mismatch')
                thread.join(8)
                if thread.is_alive(): raise AssertionError('cover stuck')
                if errors: raise errors[0]
                _,stderr=process.communicate(timeout=8)
                if process.returncode: raise AssertionError(f'fixture failed: {stderr}')
            finally:
                client.close(); cover.close()
                if process.poll() is None: process.kill(); process.wait()
                thread.join(8)
    # A well-formed ordinary TLS ClientHello fails Reality authentication and
    # must still complete a real TLS handshake with the cover server.
    run('openssl','req','-new','-x509','-key',str(path/'key.pem'),'-out',str(path/'cert.pem'),'-subj','/CN=localhost','-days','1')
    cover, cover_side=tcp_pair(); cover.settimeout(8)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); listener.listen(1)
        process=subprocess.Popen([fixture,str(listener.fileno()),path/'cert.der',path/'key.der',path/'secret',str(cover_side.fileno())],
            pass_fds=(listener.fileno(),cover_side.fileno()),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        cover_side.close(); assert len(process.stdout.readline().strip())==64
        errors=[]
        def tls_origin():
            try:
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(path/'cert.pem',path/'key.pem')
                with context.wrap_socket(cover,server_side=True) as tls:
                    if tls.recv(128)!=b'ordinary TLS request': raise AssertionError('cover request mismatch')
                    tls.sendall(b'ordinary TLS response')
                    raw=tls.unwrap(); raw.shutdown(socket.SHUT_WR); raw.close()
            except BaseException as exc: errors.append(exc)
        thread=threading.Thread(target=tls_origin); thread.start()
        try:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); context.check_hostname=False; context.verify_mode=ssl.CERT_NONE
            with context.wrap_socket(socket.create_connection(listener.getsockname()),server_hostname='localhost') as tls:
                tls.settimeout(8); tls.sendall(b'ordinary TLS request')
                if tls.recv(128)!=b'ordinary TLS response': raise AssertionError('cover response mismatch')
                raw=tls.unwrap(); raw.shutdown(socket.SHUT_WR); raw.close()
            thread.join(8)
            if thread.is_alive(): raise AssertionError('TLS cover stuck')
            if errors: raise errors[0]
            _,stderr=process.communicate(timeout=8)
            if process.returncode: raise AssertionError(f'fixture failed: {stderr}')
        finally:
            cover.close()
            if process.poll() is None: process.kill(); process.wait()
            thread.join(8)
print('Reality malformed, bounded, and ordinary TLS fallback passed')
