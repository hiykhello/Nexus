#!/usr/bin/env python3
"""Exercise bounded SOCKS UDP target authorization with real sockets."""
import contextlib
import pathlib
import socket
import subprocess
import sys
import time


def exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('control closed')
        data += part
    return data


with contextlib.ExitStack() as stack:
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    process = subprocess.Popen([str(pathlib.Path(sys.argv[1]).resolve()), 'run', str(port)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                control = stack.enter_context(socket.create_connection(('127.0.0.1', port), timeout=.2))
                break
            except OSError:
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('proxy did not start')
                time.sleep(.02)
        control.sendall(b'\x05\x01\x00')
        assert exact(control, 2) == b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        response = exact(control, 10)
        assert response[:4] == b'\x05\x00\x00\x01'
        relay = (socket.inet_ntoa(response[4:8]), int.from_bytes(response[8:], 'big'))
        client = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        client.bind(('127.0.0.1', 0))
        client.settimeout(3)
        upstreams = []
        for index in range(65):
            upstream = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            upstream.bind(('127.0.0.1', 0))
            upstream.settimeout(3)
            upstreams.append(upstream)
            header = b'\x00\x00\x00\x01\x7f\x00\x00\x01' + upstream.getsockname()[1].to_bytes(2, 'big')
            client.sendto(header + bytes([index]), relay)
            data, source = upstream.recvfrom(1024)
            if data != bytes([index]):
                raise RuntimeError(f'target {index} not reached')
        upstreams[0].sendto(b'old', source)
        upstreams[64].sendto(b'new', source)
        expected = b'\x00\x00\x00\x01\x7f\x00\x00\x01' + upstreams[64].getsockname()[1].to_bytes(2, 'big') + b'new'
        data, _ = client.recvfrom(1024)
        if data != expected:
            raise RuntimeError(f'incorrect reply after eviction: {data!r}')
        client.settimeout(.2)
        try:
            data, _ = client.recvfrom(1024)
            raise RuntimeError(f'evicted target still authorized: {data!r}')
        except socket.timeout:
            pass
        control.close()
        process.terminate()
        if process.wait(timeout=5) != 0:
            raise RuntimeError('proxy did not stop cleanly')
        print('SOCKS UDP target replacement and reply authorization passed')
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
