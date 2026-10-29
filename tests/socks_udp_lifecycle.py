#!/usr/bin/env python3
"""Exercise concurrent SOCKS UDP associations and graceful server shutdown."""
import contextlib
import pathlib
import socket
import subprocess
import sys
import time


def receive_exact(sock, size):
    result = b''
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise RuntimeError('control connection closed early')
        result += part
    return result


def associate(stack, port):
    control = stack.enter_context(socket.create_connection(('127.0.0.1', port), timeout=3))
    client = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    client.settimeout(3)
    client.bind(('127.0.0.1', 0))
    control.sendall(b'\x05\x01\x00')
    if receive_exact(control, 2) != b'\x05\x00':
        raise RuntimeError('greeting failed')
    control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
    response = receive_exact(control, 10)
    if response[:4] != b'\x05\x00\x00\x01':
        raise RuntimeError(f'association failed: {response!r}')
    relay = (socket.inet_ntoa(response[4:8]), int.from_bytes(response[8:10], 'big'))
    return control, client, relay


def exchange(association, upstream, payload):
    _, client, relay = association
    destination = upstream.getsockname()
    header = b'\x00\x00\x00\x01' + socket.inet_aton(destination[0]) + destination[1].to_bytes(2, 'big')
    client.sendto(header + payload, relay)
    data, source = upstream.recvfrom(1024)
    if data != payload:
        raise RuntimeError(f'forwarded payload: {data!r}')
    upstream.sendto(payload + b'-reply', source)
    data, reply_source = client.recvfrom(1024)
    if data != header + payload + b'-reply' or reply_source != relay:
        raise RuntimeError(f'bad reply: {data!r} from {reply_source!r}')
    return source


def wait_released(stack, addresses):
    deadline = time.monotonic() + 3
    for address in addresses:
        while True:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.bind(address)
                stack.enter_context(probe)
                break
            except OSError:
                probe.close()
                if time.monotonic() >= deadline:
                    raise RuntimeError(f'UDP socket not released: {address!r}')
                time.sleep(.01)


server = str(pathlib.Path(sys.argv[1]).resolve())
with socket.socket() as reserve:
    reserve.bind(('127.0.0.1', 0))
    port = reserve.getsockname()[1]
proc = subprocess.Popen([server, 'run', str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
try:
    deadline = time.monotonic() + 8
    while True:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                break
        except OSError:
            if proc.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('proxy did not start')
            time.sleep(.02)
    with contextlib.ExitStack() as stack:
        upstream = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        upstream.bind(('127.0.0.1', 0))
        upstream.settimeout(3)
        first = associate(stack, port)
        second = associate(stack, port)
        first_source = exchange(first, upstream, b'first')
        second_source = exchange(second, upstream, b'second')
        first[0].close()
        wait_released(stack, [first[2], first_source])
        if exchange(second, upstream, b'second-still-active') != second_source:
            raise RuntimeError('remaining association changed upstream socket')
        third = associate(stack, port)
        third_source = exchange(third, upstream, b'third')
        proc.terminate()
        if proc.wait(timeout=5) != 0:
            raise RuntimeError(f'proxy did not stop cleanly: {proc.returncode}')
        for control, _, _ in (second, third):
            if control.recv(1) != b'':
                raise RuntimeError('control connection remained open after stop')
        wait_released(stack, [second[2], second_source, third[2], third_source])
    print('SOCKS UDP concurrent associations and graceful stop passed')
finally:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
