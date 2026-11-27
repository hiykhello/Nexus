#!/usr/bin/env python3
"""Exercise single-request HTTP forwarding and hostile framing on loopback."""
import pathlib
import os
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
    sock.listen(2)
    sock.settimeout(3)
    return sock


def read_all(sock):
    data = bytearray()
    while True:
        try:
            chunk = sock.recv(65536)
        except ConnectionResetError:
            break
        if not chunk:
            break
        data += chunk
    return bytes(data)


def exchange(port, request, response, expected_prefix, expected_body, fragmented=False):
    with listener() as target:
        target_port = target.getsockname()[1]
        outcome = []
        def origin():
            try:
                with target.accept()[0] as conn:
                    conn.settimeout(3)
                    header = bytearray()
                    while not header.endswith(b'\r\n\r\n'):
                        header += conn.recv(1)
                        assert len(header) < 20000
                    outcome.append(bytes(header))
                    if fragmented:
                        for byte in response:
                            conn.sendall(bytes([byte]))
                    else:
                        conn.sendall(response)
            except Exception as exc:
                outcome.append(exc)
        thread = threading.Thread(target=origin)
        thread.start()
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                data = request.replace(b'$PORT', str(target_port).encode())
                for byte in data[:20]:
                    client.sendall(bytes([byte]))
                client.sendall(data[20:])
                received = read_all(client)
            assert received.startswith(expected_prefix), received
            body = received.split(b'\r\n\r\n', 1)[1]
            if expected_body is None:
                assert not body.endswith(b'0\r\n\r\n'), received
            else:
                assert body == expected_body, received
        finally:
            thread.join(timeout=4)
        assert not thread.is_alive() and len(outcome) == 1 and isinstance(outcome[0], bytes), outcome
        return outcome[0]


def streaming_interim(port):
    with listener() as target:
        target_port = target.getsockname()[1]
        received = threading.Event()
        outcome = []
        def origin():
            try:
                with target.accept()[0] as conn:
                    conn.settimeout(3)
                    header = bytearray()
                    while not header.endswith(b'\r\n\r\n'):
                        header += conn.recv(1)
                    conn.sendall(b'HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n')
                    assert received.wait(3), 'interim response was not forwarded promptly'
                    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
                    outcome.append(True)
            except Exception as exc:
                outcome.append(exc)
        thread = threading.Thread(target=origin)
        thread.start()
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                client.sendall(f'GET http://127.0.0.1:{target_port}/ HTTP/1.1\r\nHost: example.test\r\n\r\n'.encode())
                first = bytearray()
                while not first.endswith(b'\r\n\r\n'):
                    chunk = client.recv(1)
                    assert chunk
                    first += chunk
                assert first == b'HTTP/1.1 103 Early Hints\r\nlink: </a>\r\n\r\n', first
                received.set()
                assert read_all(client).endswith(b'\r\n\r\nOK')
        finally:
            received.set()
            thread.join(timeout=4)
        assert not thread.is_alive() and outcome == [True], outcome


def empty_response_without_upstream_close(port):
    with listener() as target:
        target_port = target.getsockname()[1]
        delivered = threading.Event()
        outcome = []
        def origin():
            try:
                with target.accept()[0] as conn:
                    conn.settimeout(3)
                    header = bytearray()
                    while not header.endswith(b'\r\n\r\n'):
                        header += conn.recv(1)
                    conn.sendall(b'HTTP/1.1 204 No Content\r\n\r\n')
                    assert delivered.wait(3), 'proxy waited for upstream close after complete response'
                    outcome.append(True)
            except Exception as exc:
                outcome.append(exc)
        thread = threading.Thread(target=origin)
        thread.start()
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                client.sendall(f'GET http://127.0.0.1:{target_port}/ HTTP/1.1\r\nHost: example.test\r\n\r\n'.encode())
                result = read_all(client)
                assert result == b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n', result
                delivered.set()
        finally:
            delivered.set()
            thread.join(timeout=4)
        assert not thread.is_alive() and outcome == [True], outcome


def run(root):
    with listener() as reserved:
        port = reserved.getsockname()[1]
    config = root / 'mixed.kdl'
    direct = 'outbound "direct" type="direct" { tcp-fast-open #true; }' if os.getenv('NEXUS_TEST_TFO_DIRECT') else 'outbound "direct" type="direct"'
    config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
{direct}
outbound "block" type="block"
routing {{ rulesets {{ "blocked" path="blocked.kdl" format="kdl"; }}; rules {{ - kind="rule-set" value="blocked" outbound="block"; }}; final "direct"; }}
''')
    (root / 'blocked.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="domain-suffix" value="blocked.test"\n')
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
        empty_response_without_upstream_close(port)
        upstream = exchange(port, b'GET http://127.0.0.1:$PORT/path?q=1 HTTP/1.1\r\nHost: other.test\r\nConnection: X-Secret, keep-alive\r\nX-Secret: remove\r\nX-Test: keep\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n',
                            b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: X-Hidden\r\nX-Hidden: remove\r\n\r\nhelloEXTRA',
                            b'HTTP/1.1 200 OK\r\n', b'hello')
        assert upstream.startswith(b'GET /path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:')
        assert b'x-secret:' not in upstream and b'x-test: keep\r\n' in upstream and b'Connection: close\r\n' in upstream
        assert b'smuggled' not in upstream
        upstream = exchange(port, b'HEAD http://127.0.0.1:$PORT HTTP/1.1\r\nHost: example.test\r\n\r\n',
                            b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello', b'HTTP/1.1 200 OK', b'')
        assert upstream.startswith(b'HEAD / HTTP/1.1\r\n')
        exchange(port, b'GET http://127.0.0.1:$PORT/ HTTP/1.1\r\nHost: example.test\r\n\r\n',
                 b'HTTP/1.1 200 OK\r\n\r\nclose-delimited', b'HTTP/1.1 200 OK', b'close-delimited')
        request = b'GET http://127.0.0.1:$PORT/ HTTP/1.1\r\nHost: example.test\r\n\r\n'
        interim = b'HTTP/1.1 103 Early Hints\r\nConnection: x-secret\r\nX-Secret: hidden\r\nLink: </a>; rel=preload\r\n\r\n'
        forwarded = b'HTTP/1.1 103 Early Hints\r\nlink: </a>; rel=preload\r\n\r\n'
        final = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'
        expected_final = b'HTTP/1.1 200 OK\r\ncontent-length: 2\r\nConnection: close\r\n\r\nOK'
        for fragmented in (False, True):
            exchange(port, request, interim + final, forwarded, expected_final, fragmented=fragmented)
        exchange(port, request, b'HTTP/1.1 100 Continue\r\n\r\n' + interim + final,
                 b'HTTP/1.1 100 Continue\r\n\r\n', forwarded + expected_final)
        bad_gateway_body = b'Bad Gateway\n'
        bad_gateway = b'HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 12\r\n\r\n' + bad_gateway_body
        streaming_interim(port)
        exchange(port, request, b'HTTP/1.1 100 Continue\r\n\r\n' * 8 + final,
                 b'HTTP/1.1 100 Continue\r\n\r\n', b'HTTP/1.1 100 Continue\r\n\r\n' * 7 + expected_final)
        exchange(port, request, interim, forwarded, bad_gateway)
        exchange(port, request, interim + b'HTTP/1.1 200', forwarded, bad_gateway)
        exchange(port, request, b'HTTP/1.1 100 Continue\r\n\r\n' * 9,
                 b'HTTP/1.1 100 Continue\r\n\r\n', b'HTTP/1.1 100 Continue\r\n\r\n' * 7 + bad_gateway)
        exchange(port, request, b'HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n',
                 b'HTTP/1.1 205 ', b'')
        exchange(port, request, b'HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\nx',
                 b'HTTP/1.1 502 ', bad_gateway_body)
        exchange(port, b'HEAD http://127.0.0.1:$PORT/ HTTP/1.1\r\nHost: example.test\r\n\r\n',
                 b'HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\nx',
                 b'HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n', b'')
        for invalid in (b'HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n',
                        b'HTTP/1.1 103 Early Hints\r\nTransfer-Encoding: chunked\r\n\r\n',
                        b'HTTP/1.1 101 Switching Protocols\r\n\r\n'):
            exchange(port, request, invalid, b'HTTP/1.1 502 ', bad_gateway_body)
        if shutil.which('curl'):
            with listener() as target:
                target_port = target.getsockname()[1]
                seen = []
                def curl_origin():
                    try:
                        with target.accept()[0] as conn:
                            conn.settimeout(3)
                            header = bytearray()
                            while not header.endswith(b'\r\n\r\n'):
                                header += conn.recv(1)
                            seen.append(bytes(header))
                            conn.sendall(b'HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;ext=yes\r\nOK\r\n0\r\nX-Trailer: dropped\r\n\r\nEXTRA')
                    except Exception as exc:
                        seen.append(exc)
                thread = threading.Thread(target=curl_origin)
                thread.start()
                try:
                    result = subprocess.run(['curl', '-fsS', '--noproxy', '', '--proxy', f'http://127.0.0.1:{port}',
                                             f'http://127.0.0.1:{target_port}/curl?q=1'], capture_output=True, timeout=5)
                    assert result.returncode == 0 and result.stdout == b'OK', result.stderr
                finally:
                    thread.join(timeout=4)
                assert not thread.is_alive() and len(seen) == 1 and isinstance(seen[0], bytes), seen
                assert seen[0].startswith(b'GET /curl?q=1 HTTP/1.1\r\n')
        exchange(port, b'GET http://127.0.0.1:$PORT/ HTTP/1.1\r\nHost: example.test\r\n\r\n',
                 b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Note: drop\r\n\r\n',
                 b'HTTP/1.1 200 OK', b'4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n', fragmented=True)
        exchange(port, b'GET http://127.0.0.1:$PORT/ HTTP/1.1\r\nHost: example.test\r\n\r\n',
                 b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\nEXTRA',
                 b'HTTP/1.1 200 OK', b'1\r\nx\r\n0\r\n\r\n')
        for body in (b'10000000000000000\r\n', b'1\r\naX', b'3\r\nab',
                     b'0\r\nInvalid trailer\r\n\r\n', b'0\r\nX: incomplete\r\n'):
            exchange(port, b'GET http://127.0.0.1:$PORT/ HTTP/1.1\r\nHost: example.test\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' + body,
                     b'HTTP/1.1 200 OK', None)
        for response in (b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx',
                         b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n'):
            exchange(port, b'GET http://127.0.0.1:$PORT/ HTTP/1.1\r\nHost: example.test\r\n\r\n', response,
                     b'HTTP/1.1 502 ', bad_gateway_body)
        for request, code in ((b'GET http://blocked.test/ HTTP/1.1\r\nHost: blocked.test\r\n\r\n', b'403'),
                              (b'GET http://blocked.test/ HTTP/1.1\r\nHost: blocked.test\r\nContent-Length: 1\r\n\r\nx', b'403'),
                              (b'GET http://blocked.test/ HTTP/1.1\r\nHost: blocked.test\r\nTransfer-Encoding: chunked\r\n\r\n', b'403'),
                              (b'GET http://blocked.test/ HTTP/1.1\r\nHost: blocked.test\r\nConnection: Host\r\n\r\n', b'400')):
            with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                client.sendall(request)
                assert read_all(client).split(b' ', 2)[1] == code
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        assert proc.returncode == 0, proc.stderr.read().decode()


with tempfile.TemporaryDirectory(prefix='nexus-http-forward-') as directory:
    run(pathlib.Path(directory))
print('HTTP forward request and response framing passed')
