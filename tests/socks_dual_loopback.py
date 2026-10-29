#!/usr/bin/env python3
"""Exercise same-port IPv4/IPv6 listeners and startup rollback."""
import contextlib
import pathlib
import socket
import subprocess
import sys
import tempfile
import time


def exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('unexpected control EOF')
        data += part
    return data


def scenario(binary, workers, occupied):
    with contextlib.ExitStack() as stack, tempfile.TemporaryDirectory() as directory:
        with socket.socket(socket.AF_INET) as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        if occupied:
            blocker = stack.enter_context(socket.socket(socket.AF_INET6))
            blocker.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            blocker.bind(('::1', port))
            blocker.listen(1)
        config = pathlib.Path(directory) / 'proxy.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "v4" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
inbound "v6" type="mixed" {{ listen host="::1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        process = subprocess.Popen([binary, 'run', '--config', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            if occupied:
                if process.wait(timeout=5) == 0:
                    raise RuntimeError('occupied IPv6 endpoint accepted')
                with socket.socket(socket.AF_INET) as check:
                    check.bind(('127.0.0.1', port))
                return
            associations = []
            for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                deadline = time.monotonic() + 5
                while True:
                    try:
                        control = stack.enter_context(socket.create_connection((host, port), timeout=.2))
                        break
                    except OSError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError('listener did not start')
                        time.sleep(.02)
                control.settimeout(3)
                control.sendall(b'\x05\x01\x00')
                assert exact(control, 2) == b'\x05\x00'
                control.sendall(b'\x05\x03\x00\x01' + bytes(4) + bytes(2))
                prefix = exact(control, 4)
                assert prefix[:3] == b'\x05\x00\x00'
                n = 4 if prefix[3] == 1 else 16
                rest = exact(control, n + 2)
                relay = (socket.inet_ntop(family, rest[:n]), int.from_bytes(rest[n:], 'big'))
                client = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
                client.bind((host, 0))
                client.settimeout(3)
                associations.append((control, client, relay))
            target = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            target.bind(('127.0.0.1', 0))
            target.settimeout(3)
            header = b'\x00\x00\x00\x01\x7f\x00\x00\x01' + target.getsockname()[1].to_bytes(2, 'big')
            for index, (_, client, relay) in enumerate(associations):
                client.sendto(header + bytes([index]), relay)
                data, source = target.recvfrom(1024)
                assert data == bytes([index])
                target.sendto(b'reply' + bytes([index]), source)
                response, _ = client.recvfrom(1024)
                assert response == header + b'reply' + bytes([index])
            associations[0][0].close()
            _, client, relay = associations[1]
            client.sendto(header + b'active', relay)
            assert target.recvfrom(1024)[0] == b'active'
            process.terminate()
            if process.wait(timeout=5) != 0:
                raise RuntimeError('server did not stop cleanly')
            for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                with socket.socket(family) as check:
                    check.settimeout(1)
                    if check.connect_ex((host, port)) == 0:
                        raise RuntimeError('listener remained open after stop')
            for (_, _, relay), family in zip(associations, (socket.AF_INET, socket.AF_INET6)):
                with socket.socket(family, socket.SOCK_DGRAM) as check:
                    check.bind(relay)
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
    for occupied in (False, True):
        scenario(binary, workers, occupied)
print('Same-port IPv4/IPv6 listeners and startup rollback passed')
