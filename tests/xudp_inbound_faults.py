"""Production VLESS Mux inbound sessions, routing and protocol faults over TLS."""
from test_paths import require_nexus
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from xudp_inbound_singbox import ROOT, UUID, exact, free_port


def wire(session, kind, payload=None, address=None):
    meta = session.to_bytes(2, 'big') + bytes((kind, payload is not None))
    if address is not None:
        meta += b'\x02' + address
    return len(meta).to_bytes(2, 'big') + meta + (len(payload).to_bytes(2, 'big') + payload if payload is not None else b'')


def read_frame(stream):
    meta = exact(stream, int.from_bytes(exact(stream, 2), 'big'))
    payload = exact(stream, int.from_bytes(exact(stream, 2), 'big')) if meta[3] & 1 else b''
    return meta, payload


def address(host, port):
    if host == 'localhost':
        return port.to_bytes(2, 'big') + b'\x02\x09localhost'
    return port.to_bytes(2, 'big') + b'\x01' + socket.inet_aton(host)


def connect(port, cert):
    context = ssl.create_default_context(cafile=str(cert))
    stream = context.wrap_socket(socket.create_connection(('127.0.0.1', port), timeout=5), server_hostname='localhost')
    stream.settimeout(5)
    stream.sendall(b'\x00' + bytes(range(16)) + b'\x00\x03')
    if exact(stream, 2) != b'\x00\x00':
        raise RuntimeError('VLESS handshake')
    return stream


with tempfile.TemporaryDirectory(prefix='nexus-xudp-inbound-faults-') as directory, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
    root = pathlib.Path(directory)
    dns.bind(('127.0.0.1', 0)); dns.settimeout(.1)
    dns_stop = threading.Event(); dns_queries = []; dns_errors = []
    def serve_dns():
        try:
            while not dns_stop.is_set():
                try: query, peer = dns.recvfrom(512)
                except socket.timeout: continue
                if query[12:] != b'\x09localhost\x00\x00\x1c\x00\x01':
                    raise RuntimeError(f'unexpected DNS query {query!r}')
                dns_queries.append(query)
                answer = (query[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + query[12:]
                          + b'\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10' + bytes(15) + b'\x01')
                dns.sendto(answer, peer)
        except Exception as exc: dns_errors.append(exc)
    dns_thread = threading.Thread(target=serve_dns, daemon=True); dns_thread.start()
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root/'key'), '-out', str(root/'cert'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-days', '1'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root/'key').chmod(0o600)
    (root/'uuid').write_text(UUID)
    (root/'uuid').chmod(0o600)
    (root/'block.kdl').write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
    port = free_port()
    (root/'config.kdl').write_text(f'''schema-version 1
role "server"
dns {{ server "test" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv6_only"; edns #false; }}
inbound "edge" type="vless" {{ listen host="127.0.0.1" port={port}; authentication {{ user "test" uuid-file="{root/'uuid'}"; }}; tls {{ certificate-file "{root/'cert'}"; private-key-file "{root/'key'}"; }}; }}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rule-set "blocked" path="{root/'block.kdl'}" format="kdl"; rule kind="rule-set" value="blocked" outbound="reject"; default-outbound "direct"; }}
''')
    server = subprocess.Popen([require_nexus(), 'run', '--config', root/'config.kdl'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while True:
            if server.poll() is not None:
                raise RuntimeError(f'server exited: {server.stderr.read()!r}')
            try:
                stream = connect(port, root/'cert')
                break
            except ConnectionRefusedError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.05)
        with stream, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as b, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as attacker:
            for s in (a, b, attacker):
                s.bind(('::1' if s.family == socket.AF_INET6 else '127.0.0.1', 0)); s.settimeout(5)
            stream.sendall(wire(1, 1, b'one', address('127.0.0.1', a.getsockname()[1])) + wire(2, 1, b'two', address('localhost', b.getsockname()[1])))
            one, source1 = a.recvfrom(100)
            two, source2 = b.recvfrom(100)
            if (one, two) != (b'one', b'two') or source1 == source2:
                raise RuntimeError('session isolation')
            if len(dns_queries) != 1 or dns_errors:
                raise RuntimeError(f'DNS fixture failed: queries={len(dns_queries)} errors={dns_errors!r}')
            attacker.sendto(b'forged', source1)
            b.sendto(b'reply2', source2); a.sendto(b'reply1', source1)
            replies = {}
            for _ in range(2):
                meta, payload = read_frame(stream)
                replies[int.from_bytes(meta[:2], 'big')] = payload
            if replies != {1: b'reply1', 2: b'reply2'}:
                raise RuntimeError(f'bad replies {replies!r}')
            stream.sendall(wire(1, 3) + wire(1, 1, b'new', address('127.0.0.1', a.getsockname()[1])) + wire(3, 1, b'blocked', address('127.0.0.2', a.getsockname()[1])))
            new, source3 = a.recvfrom(100)
            if new != b'new': raise RuntimeError('reopen')
            a.sendto(b'new-reply', source3)
            results = {}
            for _ in range(2):
                meta, payload = read_frame(stream); results[int.from_bytes(meta[:2], 'big')] = (meta[2:4], payload)
            if results.get(1) != (b'\x02\x01', b'new-reply') or results.get(3) != (b'\x03\x02', b''):
                raise RuntimeError(f'reopen or policy failure {results!r}')
            stream.sendall(b'\x00\x03')
            if stream.recv(1): raise RuntimeError('malformed frame survived')
        # Server remains available after an invalid connection.
        with connect(port, root/'cert') as stream:
            stream.sendall(wire(99, 2, b'unknown'))
            meta, payload = read_frame(stream)
            if meta != b'\x00\x63\x03\x00' or payload: raise RuntimeError('unknown session')
            # A nonzero global ID cannot safely migrate between connections.
            destination = address('127.0.0.1', 53)
            metadata = b'\x00\x04\x01\x01\x02' + destination + b'\0\0\0\0\0\0\0\x01'
            stream.sendall(len(metadata).to_bytes(2, 'big') + metadata + b'\x00\x01x')
            meta, payload = read_frame(stream)
            if meta != b'\x00\x04\x03\x02' or payload: raise RuntimeError('global ID accepted')
            # Duplicate live IDs are a protocol error, not a replacement.
            stream.sendall(wire(5, 1, None, destination) + wire(5, 1, None, destination))
            if stream.recv(1): raise RuntimeError('duplicate ID survived')
        with connect(port, root/'cert') as stream:
            server.terminate()
            if stream.recv(1): raise RuntimeError('active stream survived stop')
        server.wait(timeout=5)
        if server.returncode != 0: raise RuntimeError(f'server exit {server.returncode}: {server.stderr.read()!r}')
    finally:
        if server.poll() is None:
            server.terminate()
            try: server.wait(5)
            except subprocess.TimeoutExpired: server.kill(); server.wait()
        dns_stop.set(); dns_thread.join(2)
        if dns_thread.is_alive() or dns_errors: raise RuntimeError(f'DNS fixture cleanup: {dns_errors!r}')
print('XUDP inbound multi-session, DNS, spoof, policy, ID faults and stop passed')
