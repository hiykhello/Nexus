#!/usr/bin/env python3
"""Resolved addresses are tried in order and individually filtered."""
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

server = pathlib.Path(sys.argv[1]).resolve()
resolver = pathlib.Path(sys.argv[2]).resolve()


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise AssertionError('unexpected EOF')
        result.extend(part)
    return bytes(result)


def attempt(port, target_port, protocol, host, socks_code, http_status):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
        if protocol == 'socks':
            client.sendall(b'\x05\x01\x00')
            assert exact(client, 2) == b'\x05\x00'
            client.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + target_port.to_bytes(2, 'big'))
            head = exact(client, 4)
            exact(client, 6 if head[3] == 1 else 18)
            assert head[1] == socks_code, head
            connected = head[1] == 0
        else:
            client.sendall(b'CONNECT ' + host + b':' + str(target_port).encode() + b' HTTP/1.1\r\nHost: ' + host + b'\r\n\r\n')
            response = bytearray()
            while not response.endswith(b'\r\n\r\n'):
                response += exact(client, 1)
            status = response.split(b' ', 2)[1]
            assert status == http_status, response
            connected = status == b'200'
        if connected:
            client.sendall(b'fallback')
            assert exact(client, 8) == b'fallback'


def run(root, rule, host, socks_code, http_status, tunnel=False):
    allowed = socks_code == 0
    with socket.socket() as target, socket.socket() as refused, socket.socket() as reserved, socket.socket() as upstream:
        target.bind(('127.0.0.1', 0))
        target.listen(4)
        target.settimeout(1)
        target_port = target.getsockname()[1]
        refused.bind(('127.0.0.2', target_port))  # reserve a bound, non-listening port
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
        reserved.close()
        (root / 'rules.kdl').write_text(f'schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="{rule}"\n')
        config = root / 'config.kdl'
        extra = ''
        action = 'reject'
        if tunnel:
            upstream.bind(('127.0.0.1', 0))  # VLESS upstream deliberately refuses
            extra = f'''outbound "edge" type="vless" {{
 server host="127.0.0.1" port={upstream.getsockname()[1]}
 authentication {{ uuid-file "{root / 'user.uuid'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'ca.pem'}"; verify #true; }}
}}
'''
            action = 'edge'
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
{extra}routing {{
 rulesets {{ "blocked" path="rules.kdl" format="kdl"; }}
 rules {{ - rule-set="blocked" to="{action}"; }}
 final "direct"
}}
''')
        proc = subprocess.Popen([server, 'run', '--config', config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                env={**os.environ, 'LD_PRELOAD': str(resolver)})
        try:
            deadline = time.monotonic() + 5
            while True:
                if proc.poll() is not None:
                    raise AssertionError(proc.stderr.read().decode())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)
            accepted = []
            def echo():
                try:
                    peer, _ = target.accept()
                except TimeoutError:
                    return
                accepted.append(True)
                with peer:
                    peer.settimeout(3)
                    peer.sendall(exact(peer, 8))
            for protocol in ('socks', 'http'):
                accepted.clear()
                worker = threading.Thread(target=echo)
                worker.start()
                attempt(port, target_port, protocol, host, socks_code, http_status)
                worker.join(timeout=4)
                assert not worker.is_alive()
                assert bool(accepted) == allowed, "unexpected target connection"

        finally:
            proc.terminate()
            proc.wait(timeout=5)
            assert proc.returncode == 0, proc.stderr.read().decode()


with tempfile.TemporaryDirectory(prefix='nexus-fallback-') as directory:
    root = pathlib.Path(directory)
    forward = b'nexus-fallback.test'
    reverse = b'nexus-fallback-reversed.test'
    run(root, '192.0.2.0/24', forward, 0, b'200')  # refusal then success
    run(root, '127.0.0.2/32', forward, 0, b'200')  # blocked then success
    run(root, '127.0.0.1/32', forward, 5, b'502')  # refusal takes precedence over later block
    run(root, '127.0.0.0/8', forward, 2, b'403')   # all candidates blocked
    run(root, '127.0.0.2/32', reverse, 0, b'200')  # success stops before later block
    run(root, '127.0.0.1/32', reverse, 5, b'502')  # block then refusal
    if len(sys.argv) > 3 and sys.argv[3] == '--crypto':
        (root / 'user.uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n')
        (root / 'user.uuid').chmod(0o600)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'key.pem'), '-out', str(root / 'ca.pem'),
                        '-subj', '/CN=localhost', '-days', '1'], check=True, capture_output=True)
        run(root, '127.0.0.2/32', forward, 0, b'200', tunnel=True)  # tunnel fails, direct succeeds
        run(root, '127.0.0.1/32', forward, 4, b'502', tunnel=True)  # direct fails, tunnel fails last
print('Resolved address fallback and per-address policy passed')
