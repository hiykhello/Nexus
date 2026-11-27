#!/usr/bin/env python3
"""Exercise RFC 1929 and credential file validation through the real server."""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

server = pathlib.Path(sys.argv[1]).resolve()


def listener():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen(1)
    sock.settimeout(3)
    return sock


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise AssertionError('unexpected EOF')
        data.extend(part)
    return bytes(data)


def connect(port):
    return socket.create_connection(('127.0.0.1', port), timeout=3)


def config(port, password, inbound='socks5', username='alice'):
    return f'''schema-version 1
role "client"
inbound "local" type="{inbound}" {{
  listen host="127.0.0.1" port={port}
  authentication "password" username="{username}" password-file="{password}"
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
'''


def invalid_starts(root):
    with listener() as reserved:
        port = reserved.getsockname()[1]
    path = root / 'config.kdl'
    secret = root / 'password'
    secret.write_bytes(b'correct')
    os.chmod(secret, 0o644)
    symlink = root / 'link'
    symlink.symlink_to(secret)
    fifo = root / 'fifo'
    os.mkfifo(fifo, 0o600)
    invalid = [(secret, None, 'socks5'), (symlink, None, 'socks5'), (fifo, None, 'socks5'),
               (root / 'missing', None, 'socks5'), ('relative', None, 'socks5'),
               (secret, b'', 'socks5'), (secret, b'a\x00b', 'socks5'),
               (secret, b'a\nb\n', 'socks5'), (secret, b'x' * 256, 'socks5'),
               (secret, b'a' * 255 + b'\n\n', 'socks5')]
    for file, contents, inbound in invalid:
        if contents is not None:
            secret.write_bytes(contents)
            os.chmod(secret, 0o600)
        path.write_text(config(port, file, inbound))
        result = subprocess.run([server, 'run', '--config', path], capture_output=True, timeout=3)
        assert result.returncode != 0 and b'correct' not in result.stderr, result.stderr
        with socket.socket() as probe:
            assert probe.connect_ex(('127.0.0.1', port)) != 0


def live(root, inbound):
    secret = root / 'password'
    secret.write_bytes(b'correct\n')
    os.chmod(secret, 0o600)
    path = root / 'config.kdl'
    with listener() as reserved:
        port = reserved.getsockname()[1]
    path.write_text(config(port, secret, inbound))
    proc = subprocess.Popen([server, 'run', '--config', path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            if proc.poll() is not None:
                raise AssertionError(proc.stderr.read().decode())
            try:
                with connect(port):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.02)
        with connect(port) as client:
            client.sendall(b'\x05\x01\x00')
            assert exact(client, 2) == b'\x05\xff'
            assert client.recv(1) == b''
        # Failed authentication followed by a complete request must never dial.
        with listener() as target:
            target_port = target.getsockname()[1]
            target.settimeout(0.3)
            with connect(port) as client:
                client.sendall(b'\x05\x01\x02\x01\x05alice\x05wrong' +
                               b'\x05\x01\x00\x01\x7f\x00\x00\x01' + target_port.to_bytes(2, 'big'))
                assert exact(client, 2) == b'\x05\x02'
                try:
                    # Closing with unread CONNECT bytes may reset the socket
                    # before the authentication reply reaches the client.
                    assert exact(client, 2) == b'\x01\x01'
                    assert client.recv(1) == b''
                except ConnectionResetError:
                    pass
            try:
                peer, _ = target.accept()
            except TimeoutError:
                pass
            else:
                peer.close()
                raise AssertionError('authentication failure reached target')
        for auth in (b'\x01\x05alice\x05wrong', b'\x01\x05alice\x08correctx',
                     b'\x01\x06alicex\x07correct', b'\x01\x03bob\x07correct', b'\x02\x00',
                     b'\x01\x00', b'\x01\x05alice\x00'):
            with connect(port) as client:
                client.sendall(b'\x05\x02\x00\x02')
                assert exact(client, 2) == b'\x05\x02'
                for byte in auth:
                    client.sendall(bytes([byte]))
                assert exact(client, 2) == b'\x01\x01'
                assert client.recv(1) == b''
        with listener() as target:
            target_port = target.getsockname()[1]
            outcome = []
            def serve():
                try:
                    with target.accept()[0] as peer:
                        peer.settimeout(3)
                        assert exact(peer, 5) == b'hello'
                        peer.sendall(b'WORLD')
                    outcome.append(True)
                except Exception as error:
                    outcome.append(error)
            thread = threading.Thread(target=serve)
            thread.start()
            try:
                with connect(port) as client:
                    # Pipeline credentials, CONNECT and payload with method negotiation.
                    client.sendall(b'\x05\x02\x00\x02\x01\x05alice\x07correct' +
                                   b'\x05\x01\x00\x01\x7f\x00\x00\x01' + target_port.to_bytes(2, 'big') + b'hello')
                    assert exact(client, 2) == b'\x05\x02'
                    assert exact(client, 2) == b'\x01\x00'
                    assert exact(client, 10)[:4] == b'\x05\x00\x00\x01'
                    assert exact(client, 5) == b'WORLD'
            finally:
                thread.join(timeout=4)
            assert not thread.is_alive() and outcome == [True], outcome
        # Credentials are loaded once; a changed file applies only after restart.
        secret.write_bytes(b'changed')
        with connect(port) as client:
            client.sendall(b'\x05\x01\x02\x01\x05alice\x07correct')
            assert exact(client, 2) == b'\x05\x02'
            assert exact(client, 2) == b'\x01\x00'
        if shutil.which('curl'):
            with listener() as target:
                target_port = target.getsockname()[1]
                outcome = []
                def serve_http():
                    try:
                        with target.accept()[0] as peer:
                            peer.settimeout(3)
                            data = bytearray()
                            while not data.endswith(b'\r\n\r\n'):
                                data.extend(exact(peer, 1))
                            peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
                        outcome.append(True)
                    except Exception as error:
                        outcome.append(error)
                thread = threading.Thread(target=serve_http)
                thread.start()
                try:
                    result = subprocess.run(['curl', '-fsS', '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{port}',
                                             '--proxy-user', 'alice:correct', f'http://127.0.0.1:{target_port}/'],
                                            capture_output=True, timeout=5)
                    assert result.returncode == 0 and result.stdout == b'OK', result.stderr
                finally:
                    thread.join(timeout=4)
                assert not thread.is_alive() and outcome == [True], outcome
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        assert proc.returncode == 0, proc.stderr.read().decode()


with tempfile.TemporaryDirectory(prefix='nexus-auth-test-') as directory:
    root = pathlib.Path(directory)
    invalid_starts(root)
    for inbound in ('socks5', 'mixed'):
        live(root, inbound)
print('SOCKS5 password authentication, safe startup and relay passed on socks5 and mixed listeners')
