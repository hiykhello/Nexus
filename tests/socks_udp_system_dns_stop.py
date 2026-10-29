#!/usr/bin/env python3
"""Check SOCKS UDP ownership while system getaddrinfo is blocked."""
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

binary, shim = (str(pathlib.Path(p).resolve()) for p in sys.argv[1:3])


def exact(sock, count):
    data = b''
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise RuntimeError('unexpected control EOF')
        data += part
    return data


def event(fd, expected):
    if not select.select([fd], [], [], 3)[0] or os.read(fd, 1) != expected:
        raise RuntimeError(f'missing resolver event {expected!r}')


def scenario(workers, mode):
    with tempfile.TemporaryDirectory() as tmp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
        client.bind(('127.0.0.1', 0))
        client.settimeout(3)
        upstream.bind(('127.0.0.1', 0))
        upstream.settimeout(.4)
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        config = pathlib.Path(tmp) / 'proxy.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        ready_r, ready_w = os.pipe()
        gate_r, gate_w = os.pipe()
        env = dict(os.environ, LD_PRELOAD=shim, NEXUS_TEST_RESOLVER_READY_FD=str(ready_w),
                   NEXUS_TEST_RESOLVER_GATE_FD=str(gate_r), NEXUS_TEST_RESOLVER_DELAY_SUCCESS='1')
        process = subprocess.Popen([binary, 'run', '--config', str(config)], env=env, pass_fds=(ready_w, gate_r),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        os.close(ready_w)
        os.close(gate_r)
        released = False
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    control = socket.create_connection(('127.0.0.1', port), timeout=.2)
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('proxy did not start')
                    time.sleep(.02)
            with control:
                control.settimeout(3)
                control.sendall(b'\x05\x01\x00')
                assert exact(control, 2) == b'\x05\x00'
                control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
                response = exact(control, 10)
                assert response[:4] == b'\x05\x00\x00\x01'
                relay = (socket.inet_ntoa(response[4:8]), int.from_bytes(response[8:], 'big'))
                header = b'\x00\x00\x00\x01\x7f\x00\x00\x01' + upstream.getsockname()[1].to_bytes(2, 'big')
                client.sendto(header + b'first', relay)
                data, source = upstream.recvfrom(1024)
                if data != b'first':
                    raise RuntimeError('numeric setup failed')
                name = b'nexus-delay.test'
                client.sendto(b'\x00\x00\x00\x03' + bytes([len(name)]) + name +
                              upstream.getsockname()[1].to_bytes(2, 'big') + b'late', relay)
                event(ready_r, b'x')
                upstream.sendto(b'during-dns', source)
                data, _ = client.recvfrom(1024)
                if data != header + b'during-dns':
                    raise RuntimeError('reply stalled during system resolution')
                if mode == 'timeout':
                    time.sleep(10.3)
                elif mode == 'close':
                    control.close()
                    deadline = time.monotonic() + 3
                    while True:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                            try:
                                probe.bind(relay)
                                break
                            except OSError:
                                if time.monotonic() >= deadline:
                                    raise RuntimeError('relay remained open after control close')
                                time.sleep(.01)
                else:
                    process.terminate()
                    try:
                        process.wait(timeout=.3)
                    except subprocess.TimeoutExpired:
                        pass
                    else:
                        raise RuntimeError('server exited before resolver drained')
                os.write(gate_w, b'x')
                released = True
                event(ready_r, b'y')
                try:
                    data, _ = upstream.recvfrom(1024)
                    raise RuntimeError(f'canceled resolution sent data: {data!r}')
                except socket.timeout:
                    pass
                if mode == 'timeout':
                    client.sendto(header + b'fresh', relay)
                    data, _ = upstream.recvfrom(1024)
                    if data != b'fresh':
                        raise RuntimeError('association did not recover after timeout')
                if mode != 'stop':
                    process.terminate()
                if process.wait(timeout=5) != 0:
                    raise RuntimeError(f'proxy stop failed: {process.returncode}')
        finally:
            if process.poll() is None:
                if not released:
                    os.write(gate_w, b'x')
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            os.close(ready_r)
            os.close(gate_w)


for workers in (1, 2):
    for mode in ('close', 'timeout', 'stop'):
        scenario(workers, mode)
print('SOCKS UDP system DNS close, timeout and stop passed with one and two workers')
