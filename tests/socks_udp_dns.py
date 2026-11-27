#!/usr/bin/env python3
"""Exercise DNS resolution, concurrent replies and cancellation in SOCKS UDP."""
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
            raise RuntimeError('control connection closed')
        data += part
    return data


def bind_udp(stack):
    sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    sock.bind(('127.0.0.1', 0))
    sock.settimeout(3)
    return sock


def named(name, port, payload):
    return b'\x00\x00\x00\x03' + bytes([len(name)]) + name + port.to_bytes(2, 'big') + payload


def receive_query(dns, tcp):
    if not tcp:
        return dns.recvfrom(2048)
    connection, _ = dns.accept()
    connection.settimeout(3)
    return exact(connection, int.from_bytes(exact(connection, 2), 'big')), connection


def answer(dns, query, peer, tcp, canceled=False):
    # This fixture requests one IPv4 question without EDNS.
    response = query[:2] + b'\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00' + query[12:]
    response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x02'
    response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01'
    if tcp:
        with peer:
            if canceled:
                if peer.recv(1) != b'':
                    raise RuntimeError('canceled DNS connection still open')
            else:
                peer.sendall(len(response).to_bytes(2, 'big') + response)
    else:
        dns.sendto(response, peer)


binary = str(pathlib.Path(sys.argv[1]).resolve())
tcp = len(sys.argv) > 2 and sys.argv[2] == 'tcp'
with contextlib.ExitStack() as stack, tempfile.TemporaryDirectory() as directory:
    if tcp:
        dns = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        dns.bind(('127.0.0.1', 0))
        dns.listen(8)
        dns.settimeout(3)
    else:
        dns = bind_udp(stack)
    upstream = bind_udp(stack)
    client = bind_udp(stack)
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    config = pathlib.Path(directory) / 'proxy.kdl'
    (pathlib.Path(directory) / 'deny.kdl').write_text('schema-version 2\nkind "predicate"\n'
        'rule type="domain-suffix" value="blocked.test"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
    config.write_text(f'''schema-version 1
role "client"
dns {{ server "upstream" type="{'tcp' if tcp else 'udp'}" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rulesets {{ "deny" path="deny.kdl" format="kdl"; }}; rules {{ - kind="rule-set" value="deny" outbound="reject"; }}; final "direct"; }}
''')
    proc = subprocess.Popen([binary, 'run', '--config', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 8
        while True:
            try:
                control = stack.enter_context(socket.create_connection(('127.0.0.1', port), timeout=.2))
                break
            except OSError:
                if proc.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f'proxy did not start: {proc.poll()}')
                time.sleep(.02)
        control.settimeout(3)
        control.sendall(b'\x05\x01\x00')
        assert exact(control, 2) == b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        response = exact(control, 10)
        assert response[:4] == b'\x05\x00\x00\x01'
        relay = (socket.inet_ntoa(response[4:8]), int.from_bytes(response[8:], 'big'))
        target_port = upstream.getsockname()[1]
        header = b'\x00\x00\x00\x01\x7f\x00\x00\x01' + target_port.to_bytes(2, 'big')
        client.sendto(header + b'numeric', relay)
        data, source = upstream.recvfrom(1024)
        assert data == b'numeric'
        client.sendto(named(b'bad\x00.test', target_port, b'invalid'), relay)
        client.sendto(named(b'blocked.test', target_port, b'blocked'), relay)
        client.sendto(named(b'one.test', target_port, b'domain'), relay)
        query, dns_peer = receive_query(dns, tcp)
        assert b'\x03one\x04test\x00' in query
        upstream.sendto(b'during-dns', source)
        reply, _ = client.recvfrom(1024)
        assert reply == header + b'during-dns'
        answer(dns, query, dns_peer, tcp)
        data, domain_source = upstream.recvfrom(1024)
        assert data == b'domain' and domain_source == source
        upstream.sendto(b'answered', domain_source)
        reply, _ = client.recvfrom(1024)
        assert reply == header + b'answered'
        client.sendto(named(b'timeout.test', target_port, b'expired'), relay)
        expired_query, expired_peer = receive_query(dns, tcp)
        time.sleep(10.3)
        answer(dns, expired_query, expired_peer, tcp, canceled=True)
        client.sendto(header + b'after-timeout', relay)
        data, _ = upstream.recvfrom(1024)
        assert data == b'after-timeout'
        client.sendto(named(b'two.test', target_port, b'late'), relay)
        query, dns_peer = receive_query(dns, tcp)
        control.close()
        deadline = time.monotonic() + 3
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                try:
                    probe.bind(relay)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('relay not released during DNS cancellation')
                    time.sleep(.01)
        answer(dns, query, dns_peer, tcp, canceled=True)
        upstream.settimeout(.3)
        try:
            data, _ = upstream.recvfrom(1024)
            raise RuntimeError(f'late DNS response forwarded: {data!r}')
        except socket.timeout:
            pass
        stopping = stack.enter_context(socket.create_connection(('127.0.0.1', port), timeout=3))
        stopping.sendall(b'\x05\x01\x00')
        assert exact(stopping, 2) == b'\x05\x00'
        stopping.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        response = exact(stopping, 10)
        assert response[:4] == b'\x05\x00\x00\x01'
        stopping_relay = (socket.inet_ntoa(response[4:8]), int.from_bytes(response[8:], 'big'))
        client.sendto(named(b'stop.test', target_port, b'stopped'), stopping_relay)
        query, dns_peer = receive_query(dns, tcp)
        proc.terminate()
        if proc.wait(timeout=5) != 0:
            raise RuntimeError(f'proxy stop failed: {proc.returncode}')
        assert stopping.recv(1) == b''
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(stopping_relay)
        answer(dns, query, dns_peer, tcp, canceled=True)
        try:
            data, _ = upstream.recvfrom(1024)
            raise RuntimeError(f'DNS response after stop forwarded: {data!r}')
        except socket.timeout:
            pass
        print(f'SOCKS UDP {"TCP" if tcp else "UDP"} DNS, pending reply and cancellation passed')
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
