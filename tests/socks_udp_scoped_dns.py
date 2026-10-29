#!/usr/bin/env python3
"""Reject scoped system DNS candidates without disrupting later UDP traffic."""
import contextlib
import os
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


binary, shim = (str(pathlib.Path(p).resolve()) for p in sys.argv[1:3])
with contextlib.ExitStack() as stack:
    target = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
    target.bind(('::1', 0))
    target.settimeout(.4)
    client = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    client.bind(('127.0.0.1', 0))
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    process = subprocess.Popen([binary, 'run', str(port)], env=dict(os.environ, LD_PRELOAD=shim),
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
        control.sendall(b'\x05\x03\x00\x01' + bytes(6))
        response = exact(control, 10)
        assert response[:4] == b'\x05\x00\x00\x01'
        relay = (socket.inet_ntoa(response[4:8]), int.from_bytes(response[8:], 'big'))
        target_port = target.getsockname()[1].to_bytes(2, 'big')
        name = b'nexus-scoped.test'
        client.sendto(b'\x00\x00\x00\x03' + bytes([len(name)]) + name + target_port + b'scoped', relay)
        try:
            data, _ = target.recvfrom(1024)
            raise RuntimeError(f'scoped candidate forwarded: {data!r}')
        except socket.timeout:
            pass
        header = b'\x00\x00\x00\x04' + socket.inet_pton(socket.AF_INET6, '::1') + target_port
        client.sendto(header + b'fresh', relay)
        target.settimeout(3)
        data, source = target.recvfrom(1024)
        assert data == b'fresh'
        target.sendto(b'ok', source)
        client.settimeout(3)
        assert client.recvfrom(1024)[0] == header + b'ok'
        control.close()
        process.terminate()
        if process.wait(timeout=5) != 0:
            raise RuntimeError('proxy did not stop')
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
print('SOCKS UDP scoped DNS candidate rejected and association recovered')
