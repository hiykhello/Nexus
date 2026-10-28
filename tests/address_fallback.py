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


def attempt(port, target_port, protocol, allowed):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
        host = b'nexus-fallback.test'
        if protocol == 'socks':
            client.sendall(b'\x05\x01\x00')
            assert exact(client, 2) == b'\x05\x00'
            client.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + target_port.to_bytes(2, 'big'))
            head = exact(client, 4)
            exact(client, 6 if head[3] == 1 else 18)
            connected = head[1] == 0
        else:
            client.sendall(b'CONNECT ' + host + b':' + str(target_port).encode() + b' HTTP/1.1\r\nHost: ' + host + b'\r\n\r\n')
            response = bytearray()
            while not response.endswith(b'\r\n\r\n'):
                response += exact(client, 1)
            connected = response.split(b' ', 2)[1] == b'200'
        assert connected == allowed
        if connected:
            client.sendall(b'fallback')
            assert exact(client, 8) == b'fallback'


def run(root, rule, allowed):
    with socket.socket() as target, socket.socket() as reserved:
        target.bind(('127.0.0.1', 0))
        target.listen(4)
        target.settimeout(1)
        target_port = target.getsockname()[1]
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
        reserved.close()
        (root / 'rules.kdl').write_text(f'schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="{rule}"\n')
        config = root / 'config.kdl'
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{
 rule-set "blocked" path="rules.kdl" format="kdl"
 rule kind="rule-set" value="blocked" outbound="reject"
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
                attempt(port, target_port, protocol, allowed)
                worker.join(timeout=4)
                assert not worker.is_alive()
                assert bool(accepted) == allowed, "unexpected target connection"

        finally:
            proc.terminate()
            proc.wait(timeout=5)
            assert proc.returncode == 0, proc.stderr.read().decode()


with tempfile.TemporaryDirectory(prefix='nexus-fallback-') as directory:
    root = pathlib.Path(directory)
    run(root, '192.0.2.0/24', True)  # first address refuses; second succeeds
    run(root, '127.0.0.2/32', True)  # blocked first address is skipped
    run(root, '127.0.0.1/32', False)  # failed first address cannot bypass block
print('Resolved address fallback and per-address policy passed')
