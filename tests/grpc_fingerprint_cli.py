#!/usr/bin/env python3
"""Observe configured ClientHello and authenticated Trojan/AnyTLS traffic."""
import argparse
import json
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import threading

from detour_network import running, socks
from dns_rule_support import connect, exact, free_port, nexus_process
from anytls_network import Origin
from anytls_proxy_network import begin, reply, payload, targets_closed


def hello_details(data):
    if len(data) < 9 or data[0] != 22 or data[5] != 1:
        raise RuntimeError('not a TLS ClientHello')
    size = int.from_bytes(data[3:5], 'big')
    if len(data) != size + 5 or int.from_bytes(data[6:9], 'big') != size - 4:
        raise RuntimeError('fragmented or malformed ClientHello')
    pos = 9 + 2 + 32
    session_length = data[pos]; pos += 1 + session_length
    suite_length = int.from_bytes(data[pos:pos + 2], 'big'); pos += 2
    suites = [int.from_bytes(data[i:i + 2], 'big') for i in range(pos, pos + suite_length, 2)]
    pos += suite_length
    compression_length = data[pos]; pos += 1 + compression_length
    ext_length = int.from_bytes(data[pos:pos + 2], 'big'); pos += 2
    end = pos + ext_length
    if end != len(data): raise RuntimeError('bad extension length')
    extensions = []
    sni = None
    while pos < end:
        kind, length = int.from_bytes(data[pos:pos + 2], 'big'), int.from_bytes(data[pos + 2:pos + 4], 'big')
        pos += 4
        if pos + length > end: raise RuntimeError('truncated extension')
        extensions.append(kind)
        if kind == 0: sni = bytes(data[pos:pos + length])
        pos += length
    return suites, extensions, session_length, sni


def grease(value):
    return (value & 0x0f0f) == 0x0a0a and value >> 8 == value & 255


class Observer:
    def __init__(self, target, abort_first=False):
        self.target = target; self.stop = threading.Event(); self.messages = []; self.errors = []; self.peers = []
        self.abort_first = abort_first; self.lock = threading.Lock()
        self.listener = socket.socket(); self.listener.bind(('127.0.0.1', 0)); self.listener.listen(16); self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
    def peer(self, source):
        try:
            with source, socket.create_connection(('127.0.0.1', self.target), timeout=5) as destination:
                source.settimeout(5)
                first = exact(source, 5)
                first += exact(source, int.from_bytes(first[3:5], 'big'))
                with self.lock:
                    self.messages.append(hello_details(first))
                    abort = self.abort_first and len(self.messages) == 1
                if abort: return
                destination.sendall(first)
                source.setblocking(False); destination.setblocking(False)
                active = {source: destination, destination: source}
                while active and not self.stop.is_set():
                    readable, _, _ = select.select(list(active), [], [], .1)
                    for sock in readable:
                        data = sock.recv(65536)
                        if not data:
                            try: active[sock].shutdown(socket.SHUT_WR)
                            except OSError: pass
                            del active[sock]
                            continue
                        other = active[sock]
                        view = memoryview(data)
                        while view:
                            if not select.select([], [other], [], 5)[1]: raise TimeoutError('observer send stalled')
                            view = view[other.send(view):]
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            self.errors.append(repr(exc))
    def run(self):
        while not self.stop.is_set():
            try: incoming, _ = self.listener.accept()
            except TimeoutError: continue
            thread = threading.Thread(target=self.peer, args=(incoming,)); self.peers.append(thread); thread.start()
    def __enter__(self):
        self.thread = threading.Thread(target=self.run); self.thread.start(); return self
    def __exit__(self, kind, *_):
        self.stop.set(); self.thread.join(2); self.listener.close()
        for thread in self.peers: thread.join(6)
        if kind is None and (self.errors or any(thread.is_alive() for thread in self.peers)):
            raise RuntimeError(f'observer failure: {self.errors}')


def check(binary, root, kind, mode, route, remote, lower):
    front = free_port()
    fingerprint = '' if mode == 'default' else f'fingerprint "{mode}";'
    extra = ('tcp-fast-open #true;' if route == 'fast' else 'detour "lower";' if route == 'layered'
             else 'detour "direct";' if route in ('direct', 'direct-fast') else '')
    direct = 'outbound "direct" type="direct" { tcp-fast-open #true; }' if route == 'direct-fast' else 'outbound "direct" type="direct"'
    lower_node = f'''outbound "lower" type="trojan" {{ server host="127.0.0.1" port={lower};
 authentication {{ password-file "{root / 'password'}"; }}; tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }} }}''' if route == 'layered' else ''
    with Observer(remote) as observer, Origin(expected=1) as origin:
        config = root / 'nexus.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers 1
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
{direct}
{lower_node}
outbound "edge" type="{kind}" {{ server host="127.0.0.1" port={observer.port};
 authentication {{ uuid-file "{root / 'uuid'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; {fingerprint} verify #true; }}; {extra} transport "grpc" {{ service-name "nexus.Service"; response-policy "sing-box-lite"; }} }}
routing {{ default-outbound "edge"; }}
''')
        with nexus_process(str(binary), str(config)):
            with socks(front, 1, ('127.0.0.1', origin.port))[0] as client:
                client.settimeout(8); payload = bytes(range(256)) * 100
                client.sendall(payload)
                if exact(client, len(payload)) != payload: raise RuntimeError('business data mismatch')
                client.shutdown(socket.SHUT_WR)
                if client.recv(1): raise RuntimeError('unexpected trailing data')
            origin.wait()
        if len(observer.messages) != 1: raise RuntimeError(f'{kind}/{mode}/{route}: unexpected handshakes {len(observer.messages)}')
        suites, extensions, session_length, sni = observer.messages[0]
        if sni != b"\x00\x0c\x00\x00\x09localhost": raise RuntimeError('incorrect TLS identity')
        if mode in ('default', 'native'):
            if suites[0] != 0x1301 or any(grease(value) for value in extensions): raise RuntimeError('native ClientHello changed')
        elif not grease(suites[0]) or not grease(extensions[0]) or not grease(extensions[-1]) or extensions[0] == extensions[-1] or session_length != 32:
            raise RuntimeError(f'shaped ClientHello missing GREASE/session ID: {observer.messages!r}')
    print(f'{kind} {mode} {route}: actual ClientHello, authenticated TCP and drain passed', flush=True)
    return tuple(value for value in extensions if not grease(value))


def check_pool(binary, root, remote, lower, route):
    front = free_port()
    lower_node = f'''outbound "lower" type="trojan" {{ server host="127.0.0.1" port={lower};
 authentication {{ password-file "{root / 'password'}"; }}; tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }} }}''' if route == 'layered' else ''
    dial = 'detour "lower";' if route == 'layered' else 'tcp-fast-open #true;'
    with Observer(remote) as observer, Origin(expected=2) as origin:
        config = root / 'pool.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers 1
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
{lower_node}
outbound "edge" type="vless" {{ server host="127.0.0.1" port={observer.port};
 authentication {{ uuid-file "{root / 'uuid'}"; }}; tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; fingerprint "tls13-randomized"; verify #true; }};
 {dial} transport "grpc" {{ service-name "nexus.Service"; response-policy "sing-box-lite"; }} }}
routing {{ default-outbound "edge"; }}
''')
        with nexus_process(str(binary), str(config)):
            clients=[]
            for _ in range(2):
                client=begin(front,origin.port); reply(client); clients.append(client)
            errors=[]
            def exchange(client):
                try:
                    payload(client);client.shutdown(socket.SHUT_WR)
                    while client.recv(4096): pass
                except Exception as exc: errors.append(repr(exc))
                finally: client.close()
            threads=[threading.Thread(target=exchange,args=(client,)) for client in clients]
            for thread in threads: thread.start()
            for thread in threads: thread.join(15)
            if errors or any(thread.is_alive() for thread in threads): raise RuntimeError(f'pool streams failed: {errors}')
            targets_closed(origin,2)
            if len(observer.messages)!=1: raise RuntimeError(f'expected pooled TLS connection, got {len(observer.messages)}')
    print(f'gRPC {route}: two concurrent streams reused shaped TLS connection',flush=True)


def check_recovery(binary, root, remote, lower, route):
    front=free_port()
    lower_node=f'''outbound "lower" type="trojan" {{ server host="127.0.0.1" port={lower};
 authentication {{ password-file "{root / 'password'}"; }}; tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }} }}''' if route == 'layered' else ''
    dial='detour "lower";' if route=='layered' else 'tcp-fast-open #true;'
    with Observer(remote,abort_first=True) as observer, Origin(expected=1) as origin:
        config=root / 'recovery.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers 1
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
{lower_node}
outbound "edge" type="vless" {{ server host="127.0.0.1" port={observer.port};
 authentication {{ uuid-file "{root / 'uuid'}"; }}; tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; fingerprint "tls13-randomized"; verify #true; }};
 {dial} transport "grpc" {{ service-name "nexus.Service"; response-policy "sing-box-lite"; }} }}
routing {{ default-outbound "edge"; }}
''')
        with nexus_process(str(binary),str(config)):
            for attempt in range(2):
                try:
                    with socks(front,1,('127.0.0.1',origin.port))[0] as client:
                        client.settimeout(8); client.sendall(b'recovered');
                        if exact(client,9)!=b'recovered': raise RuntimeError('recovery payload mismatch')
                        client.shutdown(socket.SHUT_WR)
                        if client.recv(1): raise RuntimeError('recovery trailing data')
                    break
                except (RuntimeError,ConnectionError,TimeoutError):
                    if attempt: raise
            origin.wait()
        if len(observer.messages)<2: raise RuntimeError('failed connection did not create new TLS owner')
        for suites,extensions,session_size,sni in observer.messages:
            if not grease(suites[0]) or not grease(extensions[0]) or not grease(extensions[-1]) or session_size!=32 or sni!=b"\x00\x0c\x00\x00\x09localhost":
                raise RuntimeError('TLS policy not retained after failure')
    print(f'gRPC {route}: aborted TLS followed by shaped authenticated recovery',flush=True)


def check_reconnect(binary, root, kind, route, remote, lower):
    front = free_port()
    extra = 'tcp-fast-open #true;' if route == 'fast' else 'detour "lower";'
    lower_node = f'''outbound "lower" type="trojan" {{ server host="127.0.0.1" port={lower};
 authentication {{ password-file "{root / 'password'}"; }}; tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }} }}''' if route == 'layered' else ''
    with Observer(remote, abort_first=True) as observer, Origin(expected=1) as origin:
        config = root / 'reconnect.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers 1
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
{lower_node}
outbound "edge" type="{kind}" {{ server host="127.0.0.1" port={observer.port};
 authentication {{ uuid-file "{root / 'uuid'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; fingerprint "tls13-randomized"; verify #true; }}; {extra} transport "grpc" {{ service-name "nexus.Service"; response-policy "sing-box-lite"; }} }}
routing {{ default-outbound "edge"; }}
''')
        with nexus_process(str(binary), str(config)):
            with connect(front) as client:
                client.settimeout(8); client.sendall(b'\x05\x01\x00')
                if exact(client, 2) != b'\x05\x00': raise RuntimeError('SOCKS greeting failed')
                client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + origin.port.to_bytes(2, 'big'))
                if exact(client, 10)[1] == 0: raise RuntimeError('aborted first TLS connection succeeded')
            with socks(front, 1, ('127.0.0.1', origin.port))[0] as client:
                client.settimeout(8);payload = b'after-failure' * 128
                client.sendall(payload)
                if exact(client, len(payload)) != payload: raise RuntimeError('retry payload mismatch')
                client.shutdown(socket.SHUT_WR)
                if client.recv(1): raise RuntimeError('unexpected retry trailing data')
            origin.wait()
        if len(observer.messages) < 2: raise RuntimeError('fresh TLS connection was not observed')
        for suites, extensions, session_length, sni in observer.messages:
            if (not grease(suites[0]) or not grease(extensions[0]) or not grease(extensions[-1]) or
                    session_length != 32 or sni != b"\x00\x0c\x00\x00\x09localhost"):
                raise RuntimeError(f'fingerprint not retained after reconnect: {observer.messages!r}')
    print(f'{kind} {route}: failed TLS, fresh shaped connection and traffic passed', flush=True)


def check_wrong_name(binary, root, kind, remote):
    front = free_port()
    with Observer(remote) as observer, Origin(expected=0) as origin:
        config = root / 'reject.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers 1
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="{kind}" {{ server host="127.0.0.1" port={observer.port};
 authentication {{ uuid-file "{root / 'uuid'}"; }}
 tls {{ server-name "wrong.example"; ca-file "{root / 'cert'}"; fingerprint "tls13-randomized"; verify #true; }}; transport "grpc" {{ service-name "nexus.Service"; response-policy "sing-box-lite"; }} }}
routing {{ default-outbound "edge"; }}
''')
        with nexus_process(str(binary), str(config)):
            with connect(front) as client:
                client.settimeout(8); client.sendall(b'\x05\x01\x00')
                if exact(client, 2) != b'\x05\x00': raise RuntimeError('SOCKS greeting failed')
                client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + origin.port.to_bytes(2, 'big'))
                reply = exact(client, 10)
                if reply[1] == 0: raise RuntimeError('TLS hostname mismatch accepted')
        if not observer.messages: raise RuntimeError('hostname rejection did not reach TLS peer')
        if origin.peers: raise RuntimeError('hostname rejection reached business target')
    print(f'{kind} randomized: wrong TLS name rejected without reaching target', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args(); binary = args.binary.resolve(strict=True)
    revision = '824dbcfb4dd0a95921840b1737b950cde590241e'
    if f'Revision: {revision}' not in subprocess.check_output(['sing-box', 'version'], text=True): raise RuntimeError('unexpected sing-box revision')
    with tempfile.TemporaryDirectory(prefix='nexus-tls-shape-cli-') as directory:
        root = Path(directory)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'key'), '-out', str(root / 'cert'),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-days', '1'], check=True, capture_output=True)
        (root / 'password').write_text('nexus-test-password\n'); (root / 'password').chmod(0o600)
        (root / 'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f'); (root / 'uuid').chmod(0o600)
        ports = {kind: free_port() for kind in ('trojan', 'vless')}
        tls = {'enabled': True, 'certificate_path': str(root / 'cert'), 'key_path': str(root / 'key')}
        inbounds = [{'type': kind, 'listen': '127.0.0.1', 'listen_port': port,
                     'users': ([{'uuid': '00010203-0405-0607-0809-0a0b0c0d0e0f'}] if kind == 'vless' else [{'name': 'client', 'password': 'nexus-test-password'}]), 'tls': tls} for kind, port in ports.items()]
        inbounds[-1]['transport'] = {'type': 'grpc', 'service_name': 'nexus.Service'}
        inbounds[-1]['tls'] = dict(tls, alpn=['h2'])
        config = root / 'box.json'; config.write_text(json.dumps({'log': {'level': 'warn'}, 'inbounds': inbounds, 'outbounds': [{'type': 'direct'}]}))
        with running(['sing-box', 'run', '-c', str(config)], ports['trojan'], root / 'box.log'):
            random_orders = set()
            for kind in ('vless',):
                for mode in ('default', 'native', 'tls13-grease', 'tls13-randomized'):
                    routes = ('physical', 'fast', 'direct', 'direct-fast', 'layered') if mode == 'tls13-randomized' else ('physical',)
                    for route in routes:
                        order = check(binary, root, kind, mode, route, ports[kind], ports['trojan'])
                        if mode == 'tls13-randomized': random_orders.add(order)
            if len(random_orders) < 2: raise RuntimeError('randomized ClientHellos did not vary extension order')
            for route in ('fast', 'layered'):
                check_pool(binary, root, ports['vless'], ports['trojan'], route)
                check_recovery(binary, root, ports['vless'], ports['trojan'], route)
            for kind in ('vless',):
                check_wrong_name(binary, root, kind, ports[kind])



if __name__ == '__main__': main()
