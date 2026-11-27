#!/usr/bin/env python3
"""System resolver candidate cap at its boundary through a real proxy."""
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary, shim = (pathlib.Path(p).resolve() for p in sys.argv[1:3])


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise AssertionError('unexpected EOF')
        data.extend(part)
    return bytes(data)


def run(root, workers, system):
    with socket.socket() as target, socket.socket() as reserved, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        target.bind(('127.0.0.1', 0))
        target.listen(4)
        target.settimeout(.5)
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
        reserved.close()
        dns.bind(('127.0.0.1', 0))
        dns.settimeout(.1)
        stopped = threading.Event()
        queries = []
        def answer():
            while not stopped.is_set():
                try:
                    packet, peer = dns.recvfrom(4096)
                except TimeoutError:
                    continue
                count = 64 if b'nexus-64' in packet else 65
                queries.append(count)
                record = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01'
                response = packet[:2] + b'\x81\x80\x00\x01' + count.to_bytes(2, 'big') + b'\x00\x00\x00\x00' + packet[12:] + count * record
                dns.sendto(response, peer)
        dns_thread = threading.Thread(target=answer)
        if not system:
            dns_thread.start()
        config = root / 'proxy.kdl'
        dns_config = '' if system else f'dns {{ servers {{ udp "local" host="127.0.0.1" port={dns.getsockname()[1]}; }}; strategy "ipv4_only"; disable-cache #true; }}'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }} }}
outbounds {{ direct "direct"; }}
{dns_config}
routing {{ final "direct"; }}
''')
        process = subprocess.Popen([binary, 'run', '--config', config], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, env={**os.environ, 'LD_PRELOAD': str(shim)})
        try:
            deadline = time.monotonic()+5
            while True:
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read().decode())
                try:
                    client = socket.create_connection(('127.0.0.1', port), timeout=.2)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.02)
            for index, count in enumerate((64, 65, 64)):
                with client:
                    client.settimeout(3)
                    client.sendall(b'\x05\x01\x00')
                    assert exact(client, 2) == b'\x05\x00'
                    name = f'nexus-{count}.test'.encode()
                    client.sendall(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + target.getsockname()[1].to_bytes(2, 'big'))
                    reply = exact(client, 10)
                    assert reply[1] == (0 if count == 64 else 1 if system else 4), reply
                    if count == 64:
                        with target.accept()[0] as peer:
                            client.sendall(b'ping')
                            assert exact(peer, 4) == b'ping'
                    else:
                        try:
                            target.accept()[0].close()
                        except TimeoutError:
                            pass
                        else:
                            raise AssertionError('over-limit result initiated a connection')
                if index < 2:
                    client = socket.create_connection(('127.0.0.1', port), timeout=2)
            if not system:
                assert queries == [64, 65, 64], queries
        finally:
            process.terminate()
            process.wait(timeout=5)
            stopped.set()
            if not system:
                dns_thread.join(timeout=2)
                assert not dns_thread.is_alive()
            if process.returncode and sys.exc_info()[0] is None:
                raise AssertionError(process.stderr.read().decode())
            process.stderr.close()


with tempfile.TemporaryDirectory(prefix='nexus-candidate-limit-') as directory:
    for workers in (1, 2):
        for system in (True, False):
            run(pathlib.Path(directory), workers, system)
print('system and UDP resolver candidate limits and recovery passed')
