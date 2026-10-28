#!/usr/bin/env python3
"""Exercise 100-continue and rejection without external services."""
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()
workers = int(sys.argv[2]) if len(sys.argv) > 2 else 1


def listener():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen(1)
    sock.settimeout(5)
    return sock


def header(sock):
    result = bytearray()
    while not result.endswith(b'\r\n\r\n'):
        part = sock.recv(1)
        assert part and len(result) < 16384
        result += part
    return bytes(result)


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        assert part
        result += part
    return bytes(result)


def with_origin(serve, client):
    with listener() as origin:
        outcome = []
        def run():
            try:
                with origin.accept()[0] as conn:
                    conn.settimeout(5)
                    serve(conn)
                outcome.append(True)
            except Exception as exc:
                outcome.append(exc)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            client(origin.getsockname()[1])
        finally:
            thread.join(timeout=6)
        assert not thread.is_alive() and outcome == [True], outcome


def request(port, target, fields):
    sock = socket.create_connection(('127.0.0.1', port), timeout=5)
    sock.sendall((f'POST http://127.0.0.1:{target}/upload HTTP/1.1\r\nHost: test.example\r\n'
                  f'{fields}\r\n').encode())
    return sock


def exchange(port, chunked=False, early_body=False, reject=False):
    body = b'hello world'
    encoded = b'b\r\nhello world\r\n0\r\n\r\n' if chunked else body
    fields = ('Transfer-Encoding: chunked\r\n' if chunked else 'Content-Length: 11\r\n') + 'Expect: 100-Continue\r\n'
    def serve(sock):
        assert b'expect: 100-Continue\r\n' in header(sock)
        if reject:
            sock.sendall(b'HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n')
            return
        if not early_body:
            sock.settimeout(0.2)
            try:
                assert not sock.recv(1), 'request body arrived before 100'
            except TimeoutError:
                pass
            sock.settimeout(5)
            sock.sendall(b'HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n')
        assert exact(sock, len(encoded)) == encoded
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
    def client(target):
        with request(port, target, fields) as sock:
            if reject:
                assert header(sock).startswith(b'HTTP/1.1 417 ')
                return
            if early_body:
                sock.sendall(encoded)
            else:
                assert header(sock).startswith(b'HTTP/1.1 103 ')
                assert header(sock).startswith(b'HTTP/1.1 100 ')
                sock.sendall(encoded)
            assert header(sock).startswith(b'HTTP/1.1 200 ')
            assert exact(sock, 2) == b'OK'
    with_origin(serve, client)


def curl_exchange(port):
    body = b'curl-expect-upload'
    def serve(sock):
        assert b'expect: 100-continue\r\n' in header(sock).lower()
        sock.settimeout(0.2)
        try:
            assert not sock.recv(1), 'curl did not wait for 100'
        except TimeoutError:
            pass
        sock.settimeout(5)
        sock.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')
        assert exact(sock, len(body)) == body
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
    def client(target):
        result = subprocess.run(['curl', '-fsS', '--noproxy', '', '--proxy', f'http://127.0.0.1:{port}',
                                 '-H', 'Expect: 100-continue', '--expect100-timeout', '3', '--data-binary', body.decode(),
                                 f'http://127.0.0.1:{target}/upload'], capture_output=True, timeout=5)
        assert result.returncode == 0 and result.stdout == b'OK', result.stderr
    with_origin(serve, client)


def generated_error_during_upload(port):
    def serve(sock):
        header(sock)
        sock.sendall(b'not an HTTP response\r\n\r\n')
    def client(target):
        with request(port, target, 'Content-Length: 50000000\r\n') as sock:
            def sender():
                try:
                    sock.sendall(b'x' * (8 * 1024 * 1024))
                except OSError:
                    pass
            thread = threading.Thread(target=sender)
            thread.start()
            try:
                assert header(sock).startswith(b'HTTP/1.1 502 ')
            finally:
                sock.close()
                thread.join(timeout=6)
            assert not thread.is_alive()
    with_origin(serve, client)


def invalid(port):
    cases = [('Expect: other\r\n', b'417'),
             ('Expect: 100-continue, other\r\n', b'417'),
             ('Expect: 100-continue\r\nExpect: 100-continue\r\n', b'417'),
             ('Connection: Expect\r\nExpect: 100-continue\r\n', b'400'),
             ('Expect: other\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n', b'400')]
    for fields, status in cases:
        with listener() as origin:
            with request(port, origin.getsockname()[1], fields) as sock:
                assert header(sock).split(b' ', 2)[1] == status
            origin.settimeout(0.1)
            try:
                peer, _ = origin.accept()
                peer.close()
                raise AssertionError('invalid request reached origin')
            except TimeoutError:
                pass


with tempfile.TemporaryDirectory(prefix='nexus-expect-') as directory:
    with listener() as reserved:
        port = reserved.getsockname()[1]
    config = pathlib.Path(directory) / 'mixed.kdl'
    config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    proc = subprocess.Popen([binary, 'run', '--config', config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            if proc.poll() is not None:
                raise AssertionError(proc.stderr.read().decode())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.02)
        exchange(port)
        exchange(port, chunked=True)
        exchange(port, early_body=True)
        exchange(port, reject=True)
        invalid(port)
        generated_error_during_upload(port)
        if shutil.which('curl'):
            curl_exchange(port)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        assert proc.returncode == 0, proc.stderr.read().decode()
print('HTTP Expect: 100-continue, rejection and curl passed')
