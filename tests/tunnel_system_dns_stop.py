#!/usr/bin/env python3
"""A canceled outbound retains its blocking system resolver until it returns."""
import base64
import os
import pathlib
import select
import socket
import ssl
import struct
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


def sockets_owned(pid):
    result = set()
    for fd in pathlib.Path(f'/proc/{pid}/fd').iterdir():
        try:
            target = str(fd.readlink())
        except FileNotFoundError:
            continue
        if target.startswith('socket:['):
            result.add(target)
    return result


def scenario(root, protocol, workers, reset=False):
    target = socket.socket()
    target.bind(('127.0.0.1', 0))
    target.listen(2)
    target.settimeout(.7)
    target_port = target.getsockname()[1]
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    if protocol == 'vless':
        outbound = f'''outbound "edge" type="vless" {{
 server host="nexus-delay.test" port={target_port}
 authentication {{ uuid-file "{root / 'uuid'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert.pem'}"; verify #true; }}
}}'''
    else:
        outbound = f'''outbound "edge" type="shadowsocks" {{
 server host="nexus-delay.test" port={target_port}
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
    if reset:
        env['NEXUS_TEST_RESOLVER_DELAY_SUCCESS'] = '1'
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
            baseline = sockets_owned(process.pid)
            started = time.monotonic()
            client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50')
            if not select.select([ready_r], [], [], 3)[0] or os.read(ready_r, 1) != b'x':
                raise RuntimeError('outbound resolver did not enter gate')
            if reset:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                client.close()
                deadline = time.monotonic()+3
                while len(sockets_owned(process.pid)) >= len(baseline):
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('reset client socket was not released while resolver was gated')
                    time.sleep(.01)
                os.write(gate_w, b'x')
                released = True
                if not select.select([ready_r], [], [], 3)[0] or os.read(ready_r, 1) != b'y':
                    raise RuntimeError('gated resolver did not finish successfully')
                try:
                    connection, _ = target.accept()
                except TimeoutError:
                    pass
                else:
                    connection.close()
                    raise RuntimeError('canceled resolver result triggered an outbound connection')
                # A fresh tunnel must still resolve and use the same upstream
                # after the canceled resolver owner has completed.
                with socket.create_connection(('127.0.0.1', port), timeout=3) as fresh:
                    fresh.settimeout(4)
                    fresh.sendall(b'\x05\x01\x00')
                    if exact(fresh, 2) != b'\x05\x00':
                        raise RuntimeError('fresh SOCKS greeting failed')
                    released = False
                    fresh.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50ping')
                    fresh.shutdown(socket.SHUT_WR)
                    if not select.select([ready_r], [], [], 3)[0] or os.read(ready_r, 1) != b'x':
                        raise RuntimeError('fresh resolver did not enter gate')
                    os.write(gate_w, b'x')
                    released = True
                    if not select.select([ready_r], [], [], 3)[0] or os.read(ready_r, 1) != b'y':
                        raise RuntimeError('fresh resolver did not finish successfully')
                    target.settimeout(4)
                    with target.accept()[0] as upstream:
                        upstream.settimeout(4)
                        if protocol == 'vless':
                            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                            tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
                            tls_context.load_cert_chain(root / 'cert.pem', root / 'key.pem')
                            with tls_context.wrap_socket(upstream, server_side=True) as tls:
                                header = exact(tls, 26)
                                if header != b'\x00' + bytes(range(16)) + b'\x00\x01\x00\x50\x01\x7f\x00\x00\x01':
                                    raise RuntimeError('fresh VLESS request mismatch')
                                tls.sendall(b'\x00\x00')
                                if exact(fresh, 10)[:2] != b'\x05\x00':
                                    raise RuntimeError('fresh VLESS tunnel failed')
                                if exact(tls, 4) != b'ping':
                                    raise RuntimeError('pipelined VLESS upload lost during DNS')
                                tls.sendall(b'pong')
                                if exact(fresh, 4) != b'pong':
                                    raise RuntimeError('fresh VLESS download failed')
                                if tls.recv(1) != b'':
                                    raise RuntimeError('VLESS half-close did not reach upstream')
                        else:
                            if exact(fresh, 10)[:2] != b'\x05\x00':
                                raise RuntimeError('fresh Shadowsocks request failed')
                            encrypted = bytearray()
                            while True:
                                part = upstream.recv(2048)
                                if not part:
                                    break
                                encrypted.extend(part)
                            if not encrypted:
                                raise RuntimeError('Shadowsocks encrypted request missing before half-close')
            else:
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
        if not reset:
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
        target.close()


with tempfile.TemporaryDirectory(prefix='nexus-tunnel-system-dns-') as directory:
    root = pathlib.Path(directory)
    (root / 'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n')
    (root / 'uuid').chmod(0o600)
    (root / 'ss.key').write_text(base64.b64encode(bytes(range(16))).decode()+'\n')
    (root / 'ss.key').chmod(0o600)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-days', '1'], check=True, capture_output=True)
    for protocol in ('vless', 'shadowsocks'):
        for workers in (1, 2):
            for reset in (True, False):
                scenario(root, protocol, workers, reset)
print('VLESS and SS-2022 outbound system DNS reset, timeout and drained stop passed')
