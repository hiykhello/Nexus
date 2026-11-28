#!/usr/bin/env python3
"""Exercise SOCKS5 and HTTP CONNECT on one real mixed listener."""
import base64
import pathlib
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from dns_rule_support import free_port, nexus_process

server = pathlib.Path(sys.argv[1]).resolve()
workers = int(sys.argv[2]) if len(sys.argv) > 2 else 1


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise AssertionError('unexpected EOF')
        data.extend(part)
    return bytes(data)


def headers(sock):
    data = bytearray()
    while not data.endswith(b'\r\n\r\n'):
        data.extend(exact(sock, 1))
        assert len(data) <= 1024
    return bytes(data)


def listener():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen(4)
    sock.settimeout(4)
    return sock


def connect(port):
    return socket.create_connection(('127.0.0.1', port), timeout=4)


def run(root):
    with listener() as reserved:
        port = reserved.getsockname()[1]
    config = root / 'mixed.kdl'
    config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="mixed" {{
    listen host="127.0.0.1" port={port}
    authentication "none"
}}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{
    rulesets {{ "blocked" path="blocked.kdl" format="kdl"; }}
    rules {{ - rule-set="blocked" to="reject"; }}
    final "direct"
}}
''')
    (root / 'blocked.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="domain-suffix" value="blocked.test"\n')
    proc = subprocess.Popen([server, 'run', '--config', config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
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
        with listener() as target:
            target_port = target.getsockname()[1]
            outcome = []

            def serve():
                try:
                    for _ in range(2):
                        with target.accept()[0] as peer:
                            peer.settimeout(4)
                            assert exact(peer, 7) == b'payload'
                            assert peer.recv(1) == b''
                            peer.sendall(b'RESPONSE')
                    outcome.append(True)
                except Exception as error:
                    outcome.append(error)

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                with connect(port) as client:
                    request = f'CONNECT localhost:{target_port} HTTP/1.1\r\nHost: localhost:{target_port}\r\n\r\n'.encode()
                    for byte in request[:-2]:
                        client.sendall(bytes([byte]))
                    client.sendall(request[-2:] + b'payload')
                    client.shutdown(socket.SHUT_WR)
                    assert headers(client).startswith(b'HTTP/1.1 200 ')
                    assert exact(client, 8) == b'RESPONSE'
                    assert client.recv(1) == b''
                with connect(port) as client:
                    client.sendall(b'\x05\x01\x00')
                    assert exact(client, 2) == b'\x05\x00'
                    client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + target_port.to_bytes(2, 'big') + b'payload')
                    client.shutdown(socket.SHUT_WR)
                    assert exact(client, 10)[:4] == b'\x05\x00\x00\x01'
                    assert exact(client, 8) == b'RESPONSE'
            finally:
                thread.join(timeout=5)
            assert not thread.is_alive() and outcome == [True], outcome
            # The target can finish its output first while the client still
            # has data to send; both relay directions must remain alive.
            for protocol in ('connect', 'socks'):
                with connect(port) as client:
                    if protocol == 'connect':
                        client.sendall(f'CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n'.encode())
                        assert headers(client).startswith(b'HTTP/1.1 200 ')
                    else:
                        client.sendall(b'\x05\x01\x00')
                        assert exact(client, 2) == b'\x05\x00'
                        client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + target_port.to_bytes(2, 'big'))
                        assert exact(client, 10)[:2] == b'\x05\x00'
                    with target.accept()[0] as peer:
                        peer.settimeout(4)
                        peer.sendall(b'early')
                        peer.shutdown(socket.SHUT_WR)
                        assert exact(client, 5) == b'early'
                        assert client.recv(1) == b''
                        client.sendall(b'late')
                        client.shutdown(socket.SHUT_WR)
                        assert exact(peer, 4) == b'late'
                        assert peer.recv(1) == b''
        # Literal IPv6 CONNECT exercises bracket parsing and address-family dialing.
        try:
            ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            ipv6.bind(('::1', 0))
        except OSError:
            ipv6.close()
            print('IPv6 loopback unavailable; IPv6 CONNECT skipped')
        else:
            with ipv6:
                ipv6.listen(1)
                ipv6.settimeout(4)
                target_port = ipv6.getsockname()[1]
                outcome = []
                def serve_ipv6():
                    try:
                        with ipv6.accept()[0] as peer:
                            peer.sendall(exact(peer, 1))
                        outcome.append(True)
                    except Exception as error:
                        outcome.append(error)
                thread = threading.Thread(target=serve_ipv6)
                thread.start()
                try:
                    with connect(port) as client:
                        client.sendall(f'CONNECT [::1]:{target_port} HTTP/1.1\r\nHost: [::1]:{target_port}\r\n\r\nx'.encode())
                        assert headers(client).startswith(b'HTTP/1.1 200 ')
                        assert exact(client, 1) == b'x'
                finally:
                    thread.join(timeout=5)
                assert not thread.is_alive() and outcome == [True], outcome
        if shutil.which('curl'):
            with listener() as target:
                target_port = target.getsockname()[1]
                outcome = []
                def serve_http():
                    try:
                        with target.accept()[0] as peer:
                            peer.settimeout(4)
                            assert headers(peer).startswith(b'GET / HTTP/1.1')
                            peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
                        outcome.append(True)
                    except Exception as error:
                        outcome.append(error)
                thread = threading.Thread(target=serve_http)
                thread.start()
                try:
                    result = subprocess.run(['curl', '-fsS', '--noproxy', '', '--proxy', f'http://127.0.0.1:{port}',
                                             '--proxytunnel', f'http://127.0.0.1:{target_port}/'],
                                            capture_output=True, timeout=5)
                    assert result.returncode == 0 and result.stdout == b'OK', result.stderr
                finally:
                    thread.join(timeout=5)
                assert not thread.is_alive() and outcome == [True], outcome
        cases = [
            (b'CONNECT blocked.test:80 HTTP/1.1\r\nHost: blocked.test\r\n\r\n', b'403'),
            (b'CONNECT blocked.test:80 HTTP/1.1\r\nHost: other.test\r\n\r\n', b'400'),
            (b'POST http://blocked.test/ HTTP/1.1\r\nHost: blocked.test\r\n\r\n', b'403'),
            (b'CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\nx', b'501'),
            (b'X' * 16384, b'431'),
        ]
        with listener() as unused:
            unused_port = unused.getsockname()[1]  # Bound but not listening after close.
        cases.append((f'CONNECT 127.0.0.1:{unused_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'.encode(), b'502'))
        for request, status in cases:
            with connect(port) as client:
                client.sendall(request)
                assert headers(client).split(b' ', 2)[1] == status
                assert client.recv(1) == b''
        # HTTP handshake has the same total deadline as SOCKS5, even if input trickles in.
        with connect(port) as stalled:
            stalled.settimeout(12)
            stalled.sendall(b'CONNECT ')
            with connect(port) as concurrent:
                concurrent.sendall(b'\x05\x01\x00')
                assert exact(concurrent, 2) == b'\x05\x00'
            time.sleep(6)
            stalled.sendall(b'example.com:80')
            assert stalled.recv(1) == b''
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        assert proc.returncode == 0, proc.stderr.read().decode()
    (root / 'blocked.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.0/8"\nrule type="ip-cidr" value="::1/128"\n')
    with listener() as reserved:
        next_port = reserved.getsockname()[1]
    config.write_text(config.read_text().replace(f'port={port}', f'port={next_port}'))
    port = next_port
    proc = subprocess.Popen([server, 'run', '--config', config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            if proc.poll() is not None:
                raise AssertionError(proc.stderr.read().decode())
            try:
                with connect(port) as client:
                    client.sendall(b'CONNECT localhost:80 HTTP/1.1\r\nHost: localhost\r\n\r\n')
                    assert headers(client).split(b' ', 2)[1] == b'403'
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.02)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        assert proc.returncode == 0, proc.stderr.read().decode()


def password_auth(root):
    port = free_port()
    config = root / "mixed.kdl"
    secret = root / "password"
    secret.write_bytes(b"hello:world\n")
    secret.chmod(0o600)
    config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="mixed" {{
    listen host="127.0.0.1" port={port}
    authentication "password" username="alice" password-file="{secret}"
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
    valid = b"pRoXy-aUtHoRiZaTiOn: bAsIc " + base64.b64encode(b"alice:hello:world") + b"\r\n"
    invalid = b"Proxy-Authorization: Basic " + base64.b64encode(b"alice:incorrect") + b"\r\n"
    with nexus_process(server, config), listener() as target:
        address = f"127.0.0.1:{target.getsockname()[1]}"
        connect_head = f"CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n".encode()
        forward_head = f"POST http://{address}/origin HTTP/1.1\r\nHost: {address}\r\nContent-Length: 4\r\n".encode()
        for head in (connect_head, forward_head):
            for credentials in (b"", invalid, valid + valid, b"Proxy-Authorization: Basic YQ=A\r\n"):
                with connect(port) as client:
                    client.sendall(head + credentials + b"\r\n")
                    response = headers(client)
                    assert response.startswith(b"HTTP/1.1 407 "), response
                    assert b"Proxy-Authenticate: Basic " in response, response
        with connect(port) as client:
            client.sendall(connect_head + valid[:-4])
            client.sendall(valid[-4:] + b"\r\nPING")
            client.shutdown(socket.SHUT_WR)
            assert headers(client).startswith(b"HTTP/1.1 200 ")
            with target.accept()[0] as peer:
                peer.settimeout(3)
                assert exact(peer, 4) == b"PING" and peer.recv(1) == b""
                peer.sendall(b"PONG")
                peer.shutdown(socket.SHUT_WR)
                assert exact(client, 4) == b"PONG" and client.recv(1) == b""
        with connect(port) as client:
            client.sendall(forward_head + valid + b"\r\nBODY")
            with target.accept()[0] as peer:
                peer.settimeout(3)
                request = headers(peer)
                assert request.startswith(b"POST /origin HTTP/1.1\r\n")
                assert b"proxy-authorization" not in request.lower(), request
                assert exact(peer, 4) == b"BODY"
                peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                assert headers(client).startswith(b"HTTP/1.1 200 ") and exact(client, 2) == b"OK"
        with connect(port) as client:
            client.sendall(b"\x05\x02\x00\x02")
            assert exact(client, 2) == b"\x05\x02"
            client.sendall(b"\x01\x05alice\x0bhello:world")
            assert exact(client, 2) == b"\x01\x00"
            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target.getsockname()[1].to_bytes(2, "big"))
            assert exact(client, 10)[:2] == b"\x05\x00"
            with target.accept()[0] as peer:
                peer.sendall(b"authenticated SOCKS")
                assert exact(client, 19) == b"authenticated SOCKS"


with tempfile.TemporaryDirectory(prefix='nexus-mixed-test-') as directory:
    root = pathlib.Path(directory)
    if "--password" in sys.argv[3:]:
        password_auth(root)
        print("Mixed HTTP Basic and SOCKS5 authentication, fragmented CONNECT and credential stripping passed")
    else:
        run(root)
        print('Mixed SOCKS5 and HTTP CONNECT, routing and failures passed')
