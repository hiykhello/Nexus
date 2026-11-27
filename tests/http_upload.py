#!/usr/bin/env python3
"""Exercise HTTP request framing and concurrent early responses on loopback."""
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
    data = bytearray()
    while not data.endswith(b'\r\n\r\n'):
        part = sock.recv(1)
        assert part and len(data) < 16384
        data += part
    return bytes(data)


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(min(count - len(data), 65536))
        assert part, f'EOF after {len(data)} of {count} bytes'
        data += part
    return bytes(data)


def request(port, target_port, framing, body, split=False, method='POST'):
    client = socket.create_connection(('127.0.0.1', port), timeout=5)
    prefix = (f'{method} http://127.0.0.1:{target_port}/upload HTTP/1.1\r\n'
              f'Host: ignored.test\r\n{framing}\r\n').encode()
    if split:
        for byte in prefix:
            client.sendall(bytes([byte]))
        for offset in range(0, len(body), 137):
            client.sendall(body[offset:offset + 137])
    else:
        client.sendall(prefix + body)
    return client


def with_origin(handler, client):
    with listener() as target:
        outcome = []
        def run_origin():
            try:
                with target.accept()[0] as conn:
                    conn.settimeout(5)
                    handler(conn)
                outcome.append(True)
            except Exception as exc:
                outcome.append(exc)
        thread = threading.Thread(target=run_origin)
        thread.start()
        try:
            client(target.getsockname()[1])
        finally:
            thread.join(timeout=6)
        assert not thread.is_alive() and outcome == [True], outcome


def normal(port, body, chunked=False, split=False):
    wire = b'4;foo=bar\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Note: drop\r\n\r\n' if chunked else body
    expected = b'4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n' if chunked else body
    framing = 'Transfer-Encoding: chunked\r\n' if chunked else f'Content-Length: {len(body)}\r\n'
    def origin(conn):
        head = header(conn)
        assert head.startswith(b'POST /upload HTTP/1.1\r\nHost: 127.0.0.1:')
        assert exact(conn, len(expected)) == expected
        conn.settimeout(0.15)
        try:
            assert not conn.recv(1), 'forwarded bytes beyond the request body'
        except TimeoutError:
            pass
        conn.settimeout(5)
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
    def client(target_port):
        with request(port, target_port, framing, wire + b'GET /smuggled HTTP/1.1\r\n\r\n', split) as sock:
            assert header(sock).startswith(b'HTTP/1.1 200 ')
            assert exact(sock, 2) == b'OK'
    with_origin(origin, client)


def incomplete(port, framing, wire):
    def origin(conn):
        header(conn)
        data = bytearray()
        while part := conn.recv(4096):
            data += part
        assert not data.endswith(b'0\r\n\r\n')
        conn.sendall(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n')
    def client(target_port):
        with request(port, target_port, framing, wire) as sock:
            sock.shutdown(socket.SHUT_WR)
            assert header(sock).startswith(b'HTTP/1.1 400 ')
    with_origin(origin, client)


def early(port):
    delivered = threading.Event()
    def origin(conn):
        header(conn)
        conn.sendall(b'HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 413 Content Too Large\r\nContent-Length: 3\r\n\r\nno!')
        assert delivered.wait(5), 'proxy waited for the remaining upload'
    def client(target_port):
        try:
            with request(port, target_port, 'Content-Length: 10000000\r\n', b'partial') as sock:
                assert header(sock).startswith(b'HTTP/1.1 103 ')
                assert header(sock).startswith(b'HTTP/1.1 413 ')
                assert exact(sock, 3) == b'no!'
        finally:
            delivered.set()
    with_origin(origin, client)


def early_during_upload(port):
    delivered = threading.Event()
    response = b'r' * (256 * 1024)
    def origin(conn):
        header(conn)
        conn.sendall(b'HTTP/1.1 413 Content Too Large\r\nContent-Length: 262144\r\n\r\n' + response)
        assert delivered.wait(5)
    def client(target_port):
        with request(port, target_port, 'Content-Length: 50000000\r\n', b'') as sock:
            sock.settimeout(5)
            def sender():
                try:
                    sock.sendall(b'u' * (8 * 1024 * 1024))
                except OSError:
                    pass
            thread = threading.Thread(target=sender)
            thread.start()
            try:
                assert header(sock).startswith(b'HTTP/1.1 413 ')
                assert exact(sock, len(response)) == response
            finally:
                delivered.set()
                sock.close()
                thread.join(timeout=6)
            assert not thread.is_alive()
    with_origin(origin, client)


def invalid_framing(port):
    cases = [
        ('Content-Length: 1\r\nTransfer-Encoding: chunked\r\n', b'400'),
        ('Content-Length: 1\r\nContent-Length: 1\r\n', b'400'),
        ('Transfer-Encoding: gzip, chunked\r\n', b'400'),
        ('Expect: unsupported\r\nContent-Length: 1\r\n', b'417'),
    ]
    for framing, status in cases:
        with listener() as target:
            with request(port, target.getsockname()[1], framing, b'') as sock:
                assert header(sock).split(b' ', 2)[1] == status
            target.settimeout(0.1)
            try:
                peer, _ = target.accept()
                peer.close()
                raise AssertionError('invalid request reached origin')
            except TimeoutError:
                pass


def drain_limit(port):
    with listener() as target:
        outcome = []
        def origin():
            try:
                for _ in range(64):
                    with target.accept()[0] as conn:
                        conn.settimeout(5)
                        header(conn)
                        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
                outcome.append(True)
            except Exception as exc:
                outcome.append(exc)
        thread = threading.Thread(target=origin)
        thread.start()
        clients = []
        try:
            for _ in range(64):
                sock = request(port, target.getsockname()[1], '', b'', method='GET')
                clients.append(sock)
                assert header(sock).startswith(b'HTTP/1.1 200 ')
                assert not sock.recv(1)  # Server has sent FIN, but client keeps its sending side open.
            thread.join(timeout=6)
            assert not thread.is_alive() and outcome == [True], outcome
            with socket.create_connection(('127.0.0.1', port), timeout=3) as probe:
                try:
                    probe.sendall(b'\x05\x01\x00')
                    assert probe.recv(2) != b'\x05\x00'
                except ConnectionResetError:
                    pass
            time.sleep(6)
            with socket.create_connection(('127.0.0.1', port), timeout=3) as probe:
                probe.sendall(b'\x05\x01\x00')
                assert exact(probe, 2) == b'\x05\x00'
        finally:
            for sock in clients:
                sock.close()
            thread.join(timeout=6)


def curl_post(port, chunked):
    body = b'curl upload payload'
    def origin(conn):
        head = header(conn)
        assert head.startswith(b'POST /upload HTTP/1.1\r\n')
        expected = b'13\r\n' + body + b'\r\n0\r\n\r\n' if chunked else body
        assert exact(conn, len(expected)) == expected
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
    def client(target_port):
        args = ['curl', '-fsS', '--noproxy', '', '--proxy', f'http://127.0.0.1:{port}',
                '-H', 'Expect:', '--data-binary', body.decode()]
        if chunked:
            args += ['-H', 'Transfer-Encoding: chunked']
        result = subprocess.run(args + [f'http://127.0.0.1:{target_port}/upload'], capture_output=True, timeout=5)
        assert result.returncode == 0 and result.stdout == b'OK', result.stderr
    with_origin(origin, client)


with tempfile.TemporaryDirectory(prefix='nexus-upload-') as directory:
    with listener() as reserved:
        port = reserved.getsockname()[1]
    config = pathlib.Path(directory) / 'mixed.kdl'
    config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
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
        normal(port, b'a' * (1024 * 1024 + 31), split=True)
        normal(port, b'hello', split=False)
        normal(port, b'', chunked=True, split=True)
        incomplete(port, 'Content-Length: 10\r\n', b'partial')
        incomplete(port, 'Transfer-Encoding: chunked\r\n', b'1\r\naX')
        invalid_framing(port)
        early_during_upload(port)
        for _ in range(70):
            early(port)
        drain_limit(port)
        if shutil.which('curl'):
            curl_post(port, False)
            curl_post(port, True)
        # Stop while one coroutine awaits more request bytes and the other awaits a response.
        with listener() as target:
            with request(port, target.getsockname()[1], 'Content-Length: 1000\r\n', b'part') as sock:
                with target.accept()[0] as peer:
                    peer.settimeout(5)
                    header(peer)
                    assert exact(peer, 4) == b'part'
                    proc.terminate()
                    proc.wait(timeout=5)
                    assert not sock.recv(1)
                    assert not peer.recv(1)
    finally:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=5)
        assert proc.returncode == 0, proc.stderr.read().decode()
print('HTTP streaming uploads, framing and early response passed')
