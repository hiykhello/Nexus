#!/usr/bin/env python3
"""IPv4-mapped IPv6 destinations must honor both IPv4 and IPv6 block rules."""
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
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


def attempt(port, target_port, protocol, blocked, domain=False):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
        if protocol == 'socks':
            client.sendall(b'\x05\x01\x00')
            assert exact(client, 2) == b'\x05\x00'
            host = b'nexus-mapped.test'
            address = bytes([3, len(host)]) + host if domain else b'\x04' + socket.inet_pton(socket.AF_INET6, '::ffff:127.0.0.1')
            client.sendall(b'\x05\x01\x00' + address + target_port.to_bytes(2, 'big'))
            head = exact(client, 4)
            assert (head[1] == 2) == blocked, head
            exact(client, 6 if head[3] == 1 else 18)
            return head[1] == 0
        else:
            host = 'nexus-mapped.test' if domain else '[::ffff:127.0.0.1]'
            client.sendall(f'CONNECT {host}:{target_port} HTTP/1.1\r\nHost: {host}\r\n\r\n'.encode())
            response = bytearray()
            while not response.endswith(b'\r\n\r\n'):
                response += exact(client, 1)
            status = response.split(b' ', 2)[1]
            assert (status == b'403') == blocked, response
            return status == b'200'


def run(root, rule, blocked):
    with socket.socket() as target, socket.socket() as reserved:
        target.bind(('127.0.0.1', 0))
        target.listen(4)
        target.settimeout(0.2)
        target_port = target.getsockname()[1]
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
        reserved.close()
        (root / 'rules.kdl').write_text(f'schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="{rule}"\n')
        config = root / 'config.kdl'
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{
 rule-set "blocked" path="rules.kdl" format="kdl"
 rules {{ - kind="rule-set" value="blocked" outbound="reject"; }}
 default-outbound "direct"
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
            for protocol, domain in (('socks', False), ('http', False), ('socks', True), ('http', True)):
                connected = attempt(port, target_port, protocol, blocked, domain)
                try:
                    peer, _ = target.accept()
                except TimeoutError:
                    assert not connected, 'successful connection never reached target'
                else:
                    peer.close()
                    assert connected and not blocked, 'blocked or failed connection reached target'
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            assert proc.returncode == 0, proc.stderr.read().decode()


with tempfile.TemporaryDirectory(prefix='nexus-mapped-policy-') as directory:
    root = pathlib.Path(directory)
    run(root, '127.0.0.0/8', True)
    run(root, '::ffff:127.0.0.0/104', True)
    run(root, '192.0.2.0/24', False)
print('IPv4-mapped IPv6 policy enforcement passed')
