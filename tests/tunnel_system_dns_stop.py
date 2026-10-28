#!/usr/bin/env python3
"""A canceled outbound retains its blocking system resolver until it returns."""
import base64
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

binary, shim = (pathlib.Path(p).resolve() for p in sys.argv[1:3])


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count-len(data))
        if not part:
            raise RuntimeError('unexpected EOF')
        data.extend(part)
    return bytes(data)


def scenario(root, protocol, workers):
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    if protocol == 'vless':
        outbound = f'''outbound "edge" type="vless" {{
 server host="nexus-delay.test" port=443
 authentication {{ uuid-file "{root / 'uuid'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert.pem'}"; verify #true; }}
}}'''
    else:
        outbound = f'''outbound "edge" type="shadowsocks" {{
 server host="nexus-delay.test" port=443
 method "2022-blake3-aes-128-gcm"; key-file "{root / 'ss.key'}";
}}'''
    config = root / f'{protocol}-{workers}.kdl'
    config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
{outbound}
routing {{ default-outbound "edge"; }}
''')
    ready_r, ready_w = os.pipe()
    gate_r, gate_w = os.pipe()
    env = dict(os.environ, LD_PRELOAD=str(shim), NEXUS_TEST_RESOLVER_READY_FD=str(ready_w),
               NEXUS_TEST_RESOLVER_GATE_FD=str(gate_r))
    process = subprocess.Popen([binary, 'run', '--config', config], env=env, pass_fds=(ready_w, gate_r),
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    os.close(ready_w)
    os.close(gate_r)
    released = False
    try:
        deadline = time.monotonic()+5
        while True:
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            try:
                client = socket.create_connection(('127.0.0.1', port), timeout=.2)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.02)
        with client:
            client.settimeout(12)
            client.sendall(b'\x05\x01\x00')
            if exact(client, 2) != b'\x05\x00':
                raise RuntimeError('SOCKS greeting failed')
            started = time.monotonic()
            client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50')
            if not select.select([ready_r], [], [], 3)[0] or os.read(ready_r, 1) != b'x':
                raise RuntimeError('outbound resolver did not enter gate')
            if client.recv(1):
                raise RuntimeError('canceled request returned unexpected data')
            elapsed = time.monotonic()-started
            if not 8 <= elapsed <= 12:
                raise RuntimeError(f'unexpected session timeout {elapsed:.2f}s')
        # The worker remains responsive, but shutdown must retain and drain
        # the resolver owner until its blocking getaddrinfo returns.
        with socket.create_connection(('127.0.0.1', port), timeout=2) as concurrent:
            concurrent.sendall(b'\x05\x01\x00')
            if exact(concurrent, 2) != b'\x05\x00':
                raise RuntimeError('other session stalled')
        process.terminate()
        try:
            process.wait(timeout=.3)
        except subprocess.TimeoutExpired:
            pass
        else:
            raise RuntimeError('server exited while outbound resolver was gated')
        os.write(gate_w, b'x')
        released = True
        if process.wait(timeout=5) != 0:
            raise RuntimeError(process.stderr.read().decode())
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


with tempfile.TemporaryDirectory(prefix='nexus-tunnel-system-dns-') as directory:
    root = pathlib.Path(directory)
    (root / 'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n')
    (root / 'uuid').chmod(0o600)
    (root / 'ss.key').write_text(base64.b64encode(bytes(range(16))).decode()+'\n')
    (root / 'ss.key').chmod(0o600)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                    '-subj', '/CN=localhost', '-days', '1'], check=True, capture_output=True)
    for protocol in ('vless', 'shadowsocks'):
        for workers in (1, 2):
            scenario(root, protocol, workers)
print('VLESS and SS-2022 outbound system DNS timeout and drained stop passed')
