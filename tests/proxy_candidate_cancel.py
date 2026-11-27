#!/usr/bin/env python3
"""Cancel an actual proxy while its first resolved candidate is pending."""
import pathlib
import contextlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise AssertionError('unexpected EOF')
        data.extend(part)
    return bytes(data)


def pending_first(pid, port):
    owned = set()
    for fd in pathlib.Path(f'/proc/{pid}/fd').iterdir():
        try:
            name = str(fd.readlink())
        except FileNotFoundError:
            continue
        if name.startswith('socket:['):
            owned.add(name[8:-1])
    destination = f'0200007F:{port:04X}'
    count = 0
    for line in pathlib.Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if fields[2] == destination and fields[3] == '02' and fields[9] in owned:
            count += 1
    return count


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


def reset_during_dns(root, workers):
    with socket.socket() as reserved, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
        reserved.close()
        dns.bind(('127.0.0.1', 0))
        dns.settimeout(3)
        config = root / 'proxy-dns.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }} }}
outbounds {{ direct "direct"; }}
dns {{ servers {{ udp "local" host="127.0.0.1" port={dns.getsockname()[1]}; }}; strategy "ipv4_only"; disable-cache #true; }}
routing {{ final "direct"; }}
''')
        process = subprocess.Popen([binary, 'run', '--config', config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
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
            with client:
                client.settimeout(3)
                client.sendall(b'\x05\x01\x00')
                assert exact(client, 2) == b'\x05\x00'
                baseline = sockets_owned(process.pid)
                name = b'unanswered.test'
                client.sendall(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + b'\x00\x50')
                dns.recvfrom(4096)
                assert len(sockets_owned(process.pid)) > len(baseline)
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            deadline = time.monotonic() + 3
            while len(sockets_owned(process.pid)) >= len(baseline):
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError('reset client did not release its DNS and client sockets')
                time.sleep(.01)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            if process.returncode and sys.exc_info()[0] is None:
                raise AssertionError(process.stderr.read().decode())
            process.stderr.close()


def scenario(root, workers, stop_pending, clients_count=1, disconnect_one=False):
    with socket.socket() as first, socket.socket() as second, socket.socket() as live, socket.socket() as reserved, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        first.bind(('127.0.0.2', 0))
        first.listen(1)
        second.bind(('127.0.0.1', first.getsockname()[1]))
        second.listen(2)
        second.settimeout(.5)
        live.bind(('127.0.0.1', 0))
        live.listen(1)
        live.settimeout(3)
        fillers = [socket.create_connection(first.getsockname(), timeout=2) for _ in range(2)]
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
        reserved.close()
        dns.bind(('127.0.0.1', 0))
        dns.settimeout(.1)
        stop_dns = threading.Event()
        requests = []
        def serve_dns():
            while not stop_dns.is_set():
                try:
                    packet, peer = dns.recvfrom(4096)
                except TimeoutError:
                    continue
                requests.append(packet)
                record = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00'
                dns.sendto(packet[:2] + b'\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00' + packet[12:] + record + b'\x02' + record + b'\x01', peer)
        thread = threading.Thread(target=serve_dns)
        thread.start()
        config = root / 'proxy.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }} }}
outbounds {{ direct "direct"; }}
dns {{ servers {{ udp "local" host="127.0.0.1" port={dns.getsockname()[1]}; }}; strategy "ipv4_only"; disable-cache #true; }}
routing {{ final "direct"; }}
''')
        process = subprocess.Popen([binary, 'run', '--config', config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            with contextlib.ExitStack() as clients:
                sockets = []
                for _ in range(clients_count):
                    deadline = time.monotonic() + 5
                    while True:
                        if process.poll() is not None:
                            raise AssertionError(process.stderr.read().decode())
                        try:
                            client = clients.enter_context(socket.create_connection(('127.0.0.1', port), timeout=.2))
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(.02)
                    client.settimeout(3)
                    client.sendall(b'\x05\x01\x00')
                    assert exact(client, 2) == b'\x05\x00'
                    name = b'pending-candidates.test'
                    started = time.monotonic()
                    client.sendall(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + first.getsockname()[1].to_bytes(2, 'big'))
                    sockets.append(client)
                deadline = time.monotonic() + 3
                while pending_first(process.pid, first.getsockname()[1]) != clients_count:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError('not all first-candidate connects became pending')
                    time.sleep(.01)
                assert len(requests) == clients_count
                for client in sockets:
                    client.settimeout(.1)
                    try:
                        early = client.recv(10)
                    except TimeoutError:
                        pass
                    else:
                        raise AssertionError(f'first candidate did not remain pending: {early!r}')
                if disconnect_one:
                    sockets[0].setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                    sockets.pop(0).close()
                    deadline = time.monotonic() + 3
                    while pending_first(process.pid, first.getsockname()[1]) != clients_count-1:
                        if time.monotonic() >= deadline:
                            raise AssertionError('reset client did not cancel its pending candidate')
                        time.sleep(.01)
                    # A separate literal-address session must complete while
                    # the other sessions remain blocked in candidate connect.
                    with socket.create_connection(('127.0.0.1', port), timeout=3) as independent:
                        independent.settimeout(3)
                        independent.sendall(b'\x05\x01\x00')
                        assert exact(independent, 2) == b'\x05\x00'
                        independent.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + live.getsockname()[1].to_bytes(2, 'big'))
                        with live.accept()[0] as upstream:
                            upstream.settimeout(3)
                            assert exact(independent, 10)[:2] == b'\x05\x00'
                            independent.sendall(b'parallel')
                            assert exact(upstream, 8) == b'parallel'
                            upstream.sendall(b'progress')
                            assert exact(independent, 8) == b'progress'
                    assert pending_first(process.pid, first.getsockname()[1]) == clients_count-1
                if stop_pending:
                    process.terminate()
                    process.wait(timeout=5)
                    for client in sockets:
                        client.settimeout(2)
                        assert client.recv(1) == b''
                else:
                    for client in sockets:
                        client.settimeout(13)
                        response = client.recv(10)
                        if response:
                            response += exact(client, 10-len(response))
                            assert response[:2] == b'\x05\x06', response
                    assert 9 <= time.monotonic()-started < 13
                    assert process.poll() is None
                    deadline = time.monotonic() + 2
                    while pending_first(process.pid, first.getsockname()[1]):
                        if time.monotonic() >= deadline:
                            raise AssertionError('timed-out candidate socket remained owned')
                        time.sleep(.01)
                try:
                    second.accept()[0].close()
                except TimeoutError:
                    pass
                else:
                    raise AssertionError('later candidate was connected after cancellation')
                first.settimeout(.5)
                with first.accept()[0], first.accept()[0]:
                    try:
                        first.accept()[0].close()
                    except TimeoutError:
                        pass
                    else:
                        raise AssertionError('canceled first candidate remained queued')
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            stop_dns.set()
            thread.join(timeout=2)
            for filler in fillers:
                filler.close()
            if process.returncode and sys.exc_info()[0] is None:
                raise AssertionError(process.stderr.read().decode())
            process.stderr.close()
            assert not thread.is_alive()


with tempfile.TemporaryDirectory(prefix='nexus-candidate-cancel-') as directory:
    for workers in (1, 2):
        reset_during_dns(pathlib.Path(directory), workers)
        for stop_pending in (True, False):
            scenario(pathlib.Path(directory), workers, stop_pending)
            scenario(pathlib.Path(directory), workers, stop_pending, clients_count=4, disconnect_one=True)
print('pending first candidates: independent progress, disconnect, stop and timeout passed')
