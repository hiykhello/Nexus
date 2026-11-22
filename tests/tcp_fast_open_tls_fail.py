#!/usr/bin/env python3
"""Check TLS failure, deadline and cancellation on the delayed connector."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading


def check(binary, root, backend, mode):
    first = socket.socket()
    first.bind(('127.0.0.1', 0))
    first.listen(1)
    first.settimeout(3)
    second = socket.socket()
    second.bind(('127.0.0.1', 0))
    second.listen(1)
    second.settimeout(0.3)
    errors = []

    def server():
        try:
            with first.accept()[0] as peer:
                peer.settimeout(3)
                hello = peer.recv(4096)
                if not hello or hello[0] != 0x16:
                    raise RuntimeError('missing TLS ClientHello')
                if mode != 'failure':
                    while peer.recv(4096):
                        pass
        except Exception as error:
            errors.append(repr(error))

    thread = threading.Thread(target=server)
    thread.start()
    env = os.environ.copy()
    env.update(NEXUS_TEST_FAST_OPEN='1', NEXUS_TEST_FAST_OPEN_SECOND_PORT=str(second.getsockname()[1]))
    if backend == 'epoll':
        env['NEXUS_TEST_EPOLL'] = '1'
    if mode == 'timeout':
        env['NEXUS_TEST_FAST_OPEN_EXPECT_TIMEOUT'] = '1'
    else:
        env['NEXUS_TEST_FAST_OPEN_EXPECT_FAILURE'] = '1'
    if mode == 'cancel':
        env['NEXUS_TEST_FAST_OPEN_CANCEL'] = '1'
    result = subprocess.run([binary, str(first.getsockname()[1]), str(root), 'x25519'],
                            env=env, capture_output=True, text=True, timeout=6)
    thread.join(4)
    try:
        unexpected, _ = second.accept()
    except TimeoutError:
        unexpected = None
    if unexpected:
        unexpected.close()
    first.close()
    second.close()
    if result.returncode or thread.is_alive() or errors or unexpected:
        raise RuntimeError(f'{backend}/{mode}: exit={result.returncode} stderr={result.stderr!r} '
                           f'peer={errors!r} retried={bool(unexpected)}')
    print(f'{backend}/{mode}: ClientHello observed, operation drained without replay')


with tempfile.TemporaryDirectory(prefix='nexus-tfo-tls-') as directory:
    root = Path(directory) / 'root.pem'
    key = Path(directory) / 'root.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                    '-out', str(root), '-days', '1', '-subj', '/CN=Nexus TFO test CA',
                    '-addext', 'basicConstraints=critical,CA:TRUE',
                    '-addext', 'keyUsage=critical,keyCertSign,cRLSign'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for backend in ('epoll', 'uring'):
        for mode in ('failure', 'timeout', 'cancel'):
            check(sys.argv[1], root, backend, mode)
