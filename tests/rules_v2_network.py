#!/usr/bin/env python3
"""Exercise v2 rule ordering and DNS preflight through TCP and UDP SOCKS."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()


def exact(sock, n):
    result = b''
    while len(result) < n:
        chunk = sock.recv(n - len(result))
        if not chunk:
            raise RuntimeError('unexpected EOF')
        result += chunk
    return result


with tempfile.TemporaryDirectory(prefix='nexus-rules-v2-') as directory, socket.socket() as tcp, \
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, \
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
    root = pathlib.Path(directory)
    tcp.bind(('127.0.0.1', 0)); tcp.listen(8); tcp.settimeout(.1)
    port = tcp.getsockname()[1]
    udp.bind(('127.0.0.1', port)); udp.settimeout(.1)
    dns.bind(('127.0.0.1', 0)); dns.settimeout(.1)
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0)); front = reserved.getsockname()[1]
    (root/'block.kdl').write_text(f'''schema-version 2
kind "predicate"
rule type="and" {{
 rule type="domain" value="early.test"
 rule type="port" value="{port}"
 rule type="network" value="tcp"
}}
rule type="and" {{
 rule type="domain-suffix" value="late.test"
 rule type="ip-cidr" value="127.0.0.0/8"
 rule type="network" value="udp"
}}
rule type="and" {{
 rule type="domain-keyword" value="TRACK"
 rule type="network" value="tcp"
}}
rule type="and" {{
 rule type="domain-wildcard" value="*.blocked.test"
 rule type="network" value="udp"
}}
rule type="and" {{
 rule type="domain" value="family.test"
 rule type="ip-version" value="4"
 rule type="network" value="tcp"
}}
rule type="and" {{
 rule type="domain" value="private.test"
 rule type="ip-is-private" value="true"
 rule type="network" value="udp"
}}
''')
    (root/'server.kdl').write_text(f'''schema-version 1
role "server"
workers 2
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rulesets {{ "block" path="block.kdl" format="kdl"; }}; rules {{ - rule-set="block" to="reject"; }}; final "direct"; }}
''')
    stop = threading.Event(); queries = []; errors = []; packets = []
    def dns_loop():
        try:
            while not stop.is_set():
                try: packet, peer = dns.recvfrom(4096)
                except TimeoutError: continue
                queries.append(packet[12:-4])
                reply = packet[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + packet[12:]
                reply += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01'
                dns.sendto(reply, peer)
        except Exception as exc: errors.append(exc)
    def tcp_loop():
        try:
            while not stop.is_set():
                try: peer, _ = tcp.accept()
                except TimeoutError: continue
                with peer:
                    peer.settimeout(3); data = peer.recv(1024); packets.append(('tcp', data)); peer.sendall(data)
        except Exception as exc: errors.append(exc)
    def udp_loop():
        try:
            while not stop.is_set():
                try: data, peer = udp.recvfrom(1024)
                except TimeoutError: continue
                packets.append(('udp', data)); udp.sendto(data, peer)
        except Exception as exc: errors.append(exc)
    threads = [threading.Thread(target=fn) for fn in (dns_loop, tcp_loop, udp_loop)]
    for thread in threads: thread.start()
    server = subprocess.Popen([binary, 'run', '--config', root/'server.kdl'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    def connect():
        deadline = time.monotonic() + 10
        while True:
            if server.poll() is not None: raise RuntimeError(server.stderr.read())
            try: return socket.create_connection(('127.0.0.1', front), timeout=2)
            except ConnectionRefusedError:
                if time.monotonic() > deadline: raise
                time.sleep(.02)
    def greeting(client):
        client.sendall(b'\x05\x01\x00')
        if exact(client, 2) != b'\x05\x00': raise RuntimeError('SOCKS greeting')
    def target(name):
        name = name.encode()
        return b'\x03' + bytes([len(name)]) + name + port.to_bytes(2, 'big')
    def tcp_request(name, allowed):
        with connect() as client:
            greeting(client); client.sendall(b'\x05\x01\x00' + target(name))
            reply = exact(client, 10)
            if (reply[1] == 0) != allowed: raise RuntimeError(f'TCP {name}: {reply!r}')
            if allowed:
                client.sendall(name.encode())
                if exact(client, len(name)) != name.encode(): raise RuntimeError('TCP echo')
    try:
        tcp_request('early.test', False)
        if queries: raise RuntimeError(f'preflight performed DNS: {queries!r}')
        tcp_request('mytrack.test', False)
        if queries: raise RuntimeError(f'keyword preflight performed DNS: {queries!r}')
        tcp_request('family.test', False)
        if b'\x06family\x04test\x00' not in queries: raise RuntimeError('IP version rule did not wait for DNS')
        tcp_request('late.test', True)
        tcp_request('allowed.test', True)
        with connect() as control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            greeting(control); control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
            reply = exact(control, 10)
            if reply[:4] != b'\x05\x00\x00\x01': raise RuntimeError('UDP association')
            relay = (socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:10], 'big'))
            client.bind(('127.0.0.1', 0)); client.settimeout(3)
            def send(name): client.sendto(b'\x00\x00\x00' + target(name) + name.encode(), relay)
            send('early.test')
            if not client.recvfrom(1024)[0].endswith(b'early.test'): raise RuntimeError('UDP early echo')
            send('late.test'); client.settimeout(.5)
            try:
                response = client.recvfrom(1024)
                raise RuntimeError(f'blocked UDP returned {response!r}')
            except TimeoutError: pass
            send('one.blocked.test')
            try:
                response = client.recvfrom(1024)
                raise RuntimeError(f'wildcard-blocked UDP returned {response!r}')
            except TimeoutError: pass
            send('private.test')
            try:
                response = client.recvfrom(1024)
                raise RuntimeError(f'private-IP-blocked UDP returned {response!r}')
            except TimeoutError: pass
            if b'\x07private\x04test\x00' not in queries: raise RuntimeError('private-IP rule did not wait for DNS')
            client.settimeout(3); send('allowed.test')
            if not client.recvfrom(1024)[0].endswith(b'allowed.test'): raise RuntimeError('UDP recovery')
            send('two.one.blocked.test')
            if not client.recvfrom(1024)[0].endswith(b'two.one.blocked.test'): raise RuntimeError('UDP wildcard depth')
        expected = [('tcp', b'late.test'), ('tcp', b'allowed.test'), ('udp', b'early.test'), ('udp', b'allowed.test'),
                    ('udp', b'two.one.blocked.test')]
        if packets != expected or errors: raise RuntimeError(f'packets={packets!r}, errors={errors!r}')
        if b'\x04late\x04test\x00' not in queries: raise RuntimeError('missing DNS for late rule')
        server.terminate(); server.wait(timeout=5)
        if server.returncode: raise RuntimeError(server.stderr.read())
        print('v2 TCP/UDP routing, DNS preflight, resolved IP and recovery passed')
    finally:
        if server.poll() is None: server.terminate(); server.wait(timeout=5)
        server.stderr.close(); stop.set()
        for thread in threads: thread.join(timeout=3)
