#!/usr/bin/env python3
"""Exercise a real proxy with a saturated loopback accept queue."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()


def exact(sock, length):
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise AssertionError('unexpected EOF')
        result.extend(part)
    return bytes(result)


def start(config, port):
    process = subprocess.Popen([binary, 'run', '--config', config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 5
    while True:
        if process.poll() is not None:
            raise AssertionError(process.stderr.read().decode())
        try:
            client = socket.create_connection(('127.0.0.1', port), timeout=.2)
            return process, client
        except OSError:
            if time.monotonic() >= deadline:
                process.kill()
                process.wait()
                raise
            time.sleep(.02)


def handshake(client):
    client.settimeout(3)
    client.sendall(b'\x05\x01\x00')
    assert exact(client, 2) == b'\x05\x00'


def socket_fds(directory):
    sockets = set()
    for entry in directory.iterdir():
        try:
            target = str(entry.readlink())
        except FileNotFoundError:
            continue
        if target.startswith('socket:['):
            sockets.add(target)
    return sockets


def scenario(root, workers, stop_pending):
    with socket.socket() as target, socket.socket() as reserved:
        target.bind(('127.0.0.1', 0))
        target.listen(1)
        fillers = [socket.create_connection(target.getsockname(), timeout=2) for _ in range(2)]
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
        reserved.close()
        config = root / 'proxy.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }} }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
        process, client = start(config, port)
        try:
            with client:
                handshake(client)
                fd_directory = pathlib.Path(f'/proc/{process.pid}/fd')
                baseline_sockets = socket_fds(fd_directory)
                destination = target.getsockname()[1]
                started = time.monotonic()
                client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + destination.to_bytes(2, 'big'))
                client.settimeout(.3)
                try:
                    early = client.recv(10)
                except TimeoutError:
                    pass
                else:
                    raise AssertionError(f'connect was not pending: {early!r}')
                if stop_pending:
                    process.terminate()
                    process.wait(timeout=5)
                    client.settimeout(2)
                    assert client.recv(1) == b''
                else:
                    client.settimeout(13)
                    response = client.recv(10)
                    # The connection timer and session sweeper share the 10 s deadline.
                    # The sweeper may close the client before a SOCKS error is delivered.
                    if response:
                        response += exact(client, 10-len(response))
                        assert response[:2] == b'\x05\x06', response
                    assert 9 <= time.monotonic() - started < 13
                    assert process.poll() is None
                    with socket.create_connection(('127.0.0.1', port), timeout=2) as another:
                        handshake(another)
                    fd_deadline = time.monotonic() + 2
                    # The baseline included this client's accepted socket; it
                    # must be gone along with the in-flight target socket.
                    while len(socket_fds(fd_directory)) >= len(baseline_sockets):
                        if time.monotonic() >= fd_deadline:
                            raise AssertionError(f'proxy did not release connection sockets: {baseline_sockets} -> {socket_fds(fd_directory)}')
                        time.sleep(.02)
                    target.settimeout(.5)
                    with target.accept()[0], target.accept()[0]:
                        try:
                            target.accept()[0].close()
                        except TimeoutError:
                            pass
                        else:
                            raise AssertionError('timed-out connect remained queued')
            if stop_pending:
                assert process.returncode == 0, process.stderr.read().decode()
                process.stderr.close()
                with socket.socket() as next_port:
                    next_port.bind(('127.0.0.1', 0))
                    replacement = next_port.getsockname()[1]
                config.write_text(config.read_text().replace(f'port={port}', f'port={replacement}'))
                port = replacement
                process, restarted = start(config, port)
                with restarted:
                    handshake(restarted)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            for filler in fillers:
                filler.close()
            if process.returncode and sys.exc_info()[0] is None:
                raise AssertionError(process.stderr.read().decode())
            process.stderr.close()


with tempfile.TemporaryDirectory(prefix='nexus-pending-connect-') as tmp:
    for workers in (1, 2):
        for stop_pending in (True, False):
            scenario(pathlib.Path(tmp), workers, stop_pending)
print('pending direct connect: stop, restart and timeout passed')
