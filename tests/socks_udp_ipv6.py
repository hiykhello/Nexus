#!/usr/bin/env python3
"""Exercise an IPv6 SOCKS control and UDP client against dual-stack targets."""
import contextlib
import pathlib
import socket
import subprocess
import sys
import tempfile
import time


def exact(sock, count):
    data = b''
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RuntimeError('unexpected control EOF')
        data += chunk
    return data


def scenario(binary, workers, inbound):
    with contextlib.ExitStack() as stack, tempfile.TemporaryDirectory() as directory:
        with socket.socket(socket.AF_INET6) as probe:
            probe.bind(('::1', 0))
            port = probe.getsockname()[1]
        config = pathlib.Path(directory) / 'proxy.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="{inbound}" {{ listen host="::1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
        process = subprocess.Popen([binary, 'run', '--config', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 8
            while True:
                try:
                    control = stack.enter_context(socket.create_connection(('::1', port), timeout=.2))
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('IPv6 listener did not start')
                    time.sleep(.02)
            control.settimeout(3)
            client = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
            attacker = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
            client.bind(('::1', 0))
            attacker.bind(('::1', 0))
            client.settimeout(3)
            control.sendall(b'\x05\x01\x00')
            assert exact(control, 2) == b'\x05\x00'
            control.sendall(b'\x05\x03\x00\x04' + bytes(16) + b'\x00\x00')
            response = exact(control, 22)
            assert response[:4] == b'\x05\x00\x00\x04'
            relay = (socket.inet_ntop(socket.AF_INET6, response[4:20]), int.from_bytes(response[20:], 'big'))
            for family, host, address_type in ((socket.AF_INET, '127.0.0.1', 1), (socket.AF_INET6, '::1', 4)):
                upstream = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
                upstream.bind((host, 0))
                upstream.settimeout(3)
                header = b'\x00\x00\x00' + bytes([address_type]) + socket.inet_pton(family, host) + upstream.getsockname()[1].to_bytes(2, 'big')
                wire = header + b'hello'
                client.sendto(wire, relay)
                data, source = upstream.recvfrom(1024)
                assert data == b'hello'
                attacker.sendto(wire, relay)
                upstream.sendto(b'world', source)
                response, _ = client.recvfrom(1024)
                assert response == header + b'world'
                upstream.settimeout(.15)
                try:
                    upstream.recvfrom(1024)
                    raise RuntimeError('other IPv6 client port forwarded')
                except socket.timeout:
                    pass
                if family == socket.AF_INET6:
                    payload = b'x' * 65500
                    upstream.sendto(payload, source)
                    response, _ = client.recvfrom(65535)
                    assert response == header + payload
                    upstream.sendto(b'x' * 65505, source)
                    response, _ = client.recvfrom(65535)
                    assert response == header + b'x' * 65505
                    upstream.sendto(b'x' * 65506, source)
                    client.settimeout(.15)
                    try:
                        client.recvfrom(65535)
                        raise RuntimeError('oversized IPv6 SOCKS UDP reply delivered')
                    except socket.timeout:
                        pass
                    finally:
                        client.settimeout(3)
            upstream4 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            upstream4.bind(('127.0.0.1', 0))
            upstream4.settimeout(3)
            name = b'127.0.0.1'
            client.sendto(b'\x00\x00\x00\x03' + bytes([len(name)]) + name +
                          upstream4.getsockname()[1].to_bytes(2, 'big') + b'domain', relay)
            data, source = upstream4.recvfrom(1024)
            assert data == b'domain'
            upstream4.sendto(b'resolved', source)
            response, _ = client.recvfrom(1024)
            assert response == (b'\x00\x00\x00\x01\x7f\x00\x00\x01' +
                                upstream4.getsockname()[1].to_bytes(2, 'big') + b'resolved')
            control.close()
            deadline = time.monotonic() + 3
            while True:
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
                    try:
                        probe.bind(relay)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError('IPv6 relay not released')
                        time.sleep(.01)
            with socket.create_connection(('::1', port), timeout=3) as bad_hint:
                bad_hint.sendall(b'\x05\x01\x00')
                assert exact(bad_hint, 2) == b'\x05\x00'
                bad_hint.sendall(b'\x05\x03\x00\x04' + socket.inet_pton(socket.AF_INET6, '::2') + b'\x00\x00')
                assert exact(bad_hint, 10)[:2] == b'\x05\x02'
            with socket.socket() as tcp_target:
                tcp_target.bind(('127.0.0.1', 0))
                tcp_target.listen(1)
                tcp_target.settimeout(3)
                with socket.create_connection(('::1', port), timeout=3) as tcp_client:
                    tcp_client.sendall(b'\x05\x01\x00')
                    assert exact(tcp_client, 2) == b'\x05\x00'
                    tcp_client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + tcp_target.getsockname()[1].to_bytes(2, 'big'))
                    with tcp_target.accept()[0] as accepted:
                        accepted.settimeout(3)
                        assert exact(tcp_client, 10)[:2] == b'\x05\x00'
                        tcp_client.sendall(b'ping')
                        assert exact(accepted, 4) == b'ping'
                        accepted.sendall(b'pong')
                        assert exact(tcp_client, 4) == b'pong'
            process.terminate()
            if process.wait(timeout=5) != 0:
                raise RuntimeError('server did not stop cleanly')
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


binary = str(pathlib.Path(sys.argv[1]).resolve())
for workers in (1, 2):
    for inbound in ('socks5', 'mixed'):
        scenario(binary, workers, inbound)
print('IPv6 SOCKS/Mixed UDP associations passed with one and two workers')
