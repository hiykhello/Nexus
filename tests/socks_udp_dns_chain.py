#!/usr/bin/env python3
"""Exercise SOCKS UDP DNS bootstrap retry and cancellation at each hop."""
import contextlib
import pathlib
import socket
import subprocess
import sys
import tempfile
import time


def exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('unexpected EOF')
        data += part
    return data


def udp(stack):
    sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    sock.bind(('127.0.0.1', 0))
    sock.settimeout(3)
    return sock


def reply(query, addresses):
    result = bytearray(query)
    result[2:4] = b'\x81\x80'
    result[6:8] = len(addresses).to_bytes(2, 'big')
    for last in addresses:
        result.extend(b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00' + bytes([last]))
    return result


def associate(stack, port):
    control = stack.enter_context(socket.create_connection(('127.0.0.1', port), timeout=3))
    control.sendall(b'\x05\x01\x00')
    assert exact(control, 2) == b'\x05\x00'
    control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
    result = exact(control, 10)
    assert result[:4] == b'\x05\x00\x00\x01'
    return control, (socket.inet_ntoa(result[4:8]), int.from_bytes(result[8:], 'big'))


def send(client, relay, port, name):
    client.sendto(b'\x00\x00\x00\x03' + bytes([len(name)]) + name + port.to_bytes(2, 'big') + b'payload', relay)


def wait_release(relay):
    deadline = time.monotonic() + 3
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind(relay)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('relay did not close')
                time.sleep(.01)


def scenario(binary, workers):
    with contextlib.ExitStack() as stack, tempfile.TemporaryDirectory() as tmp:
        root, client, target = udp(stack), udp(stack), udp(stack)
        leaf = stack.enter_context(socket.socket())
        leaf.bind(('127.0.0.1', 0))
        leaf.listen(8)
        leaf.settimeout(3)
        refused = stack.enter_context(socket.socket())
        refused.bind(('127.0.0.2', leaf.getsockname()[1]))
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        config = pathlib.Path(tmp) / 'proxy.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
dns {{
 server "leaf" type="tcp" host="leaf.test" port={leaf.getsockname()[1]} domain-resolver="root"
 server "root" type="udp" host="127.0.0.1" port={root.getsockname()[1]}
 strategy "ipv4_only"
 disable-cache #true
}}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        process = subprocess.Popen([binary, 'run', '--config', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    control, relay = associate(stack, port)
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('proxy did not start')
                    time.sleep(.02)
            target_port = target.getsockname()[1]
            send(client, relay, target_port, b'target.test')
            query, peer = root.recvfrom(2048)
            assert query[12:-4] == b'\x04leaf\x04test\x00'
            root.sendto(reply(query, (2, 1)), peer)
            with leaf.accept()[0] as connection:
                connection.settimeout(3)
                query = exact(connection, int.from_bytes(exact(connection, 2), 'big'))
                assert query[12:-4] == b'\x06target\x04test\x00'
                response = reply(query, (1,))
                connection.sendall(len(response).to_bytes(2, 'big') + response)
            data, source = target.recvfrom(1024)
            assert data == b'payload'
            target.sendto(b'answer', source)
            wire, _ = client.recvfrom(1024)
            assert wire == b'\x00\x00\x00\x01\x7f\x00\x00\x01' + target_port.to_bytes(2, 'big') + b'answer'
            control.close()
            wait_release(relay)
            # Cancel during the bootstrap query. A late answer must not start leaf DNS.
            control, relay = associate(stack, port)
            send(client, relay, target_port, b'cancel-root.test')
            query, peer = root.recvfrom(2048)
            control.close()
            wait_release(relay)
            root.sendto(reply(query, (1,)), peer)
            leaf.settimeout(.3)
            try:
                conn, _ = leaf.accept()
                conn.close()
                raise RuntimeError('canceled bootstrap started leaf DNS')
            except socket.timeout:
                pass
            leaf.settimeout(3)
            # Cancel while the leaf's TCP query is pending.
            control, relay = associate(stack, port)
            send(client, relay, target_port, b'cancel-leaf.test')
            query, peer = root.recvfrom(2048)
            root.sendto(reply(query, (1,)), peer)
            with leaf.accept()[0] as connection:
                connection.settimeout(3)
                query = exact(connection, int.from_bytes(exact(connection, 2), 'big'))
                assert query[12:-4] == b'\x0bcancel-leaf\x04test\x00'
                control.close()
                wait_release(relay)
                if connection.recv(1) != b'':
                    raise RuntimeError('leaf DNS connection not canceled')
            target.settimeout(.3)
            try:
                target.recvfrom(1024)
                raise RuntimeError('canceled DNS forwarded target packet')
            except socket.timeout:
                pass
            process.terminate()
            if process.wait(timeout=5) != 0:
                raise RuntimeError('proxy did not stop cleanly')
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


binary = str(pathlib.Path(sys.argv[1]).resolve())
for count in (1, 2):
    scenario(binary, count)
print('SOCKS UDP DNS bootstrap retry and per-hop cancellation passed')
