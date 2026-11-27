#!/usr/bin/env python3
"""First proxied UDP replies, two slots, association recovery and active stop."""
import argparse
import base64
import contextlib
import hashlib
import json
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

for parent in Path(__file__).resolve().parents:
    if (parent / 'tests/dns_rule_support.py').is_file():
        sys.path.insert(0, str(parent / 'tests'))
        break
from dns_rule_support import connect, exact, free_port, nexus_process, proxy_client
from detour_network import running


def address(target):
    return b'\x01' + socket.inet_aton(target[0]) + struct.pack('!H', target[1])


@contextlib.contextmanager
def packet_client(kind, root, front, serial):
    with contextlib.ExitStack() as stack:
        if kind == 'trojan':
            context = ssl.create_default_context(cafile=str(root / 'cert'))
            raw = stack.enter_context(connect(front))
            control = stack.enter_context(context.wrap_socket(raw, server_hostname='localhost'))
            control.settimeout(3)
            control.sendall(hashlib.sha224(b'secret').hexdigest().encode() +
                            b'\r\n\x03\x01' + bytes(6) + b'\r\n')

            def send(target, payload):
                control.sendall(address(target) + struct.pack('!H', len(payload)) + b'\r\n' + payload)

            def receive(target, payload):
                if exact(control, 7) != address(target):
                    raise RuntimeError('Trojan reply source mismatch')
                size = int.from_bytes(exact(control, 2), 'big')
                if exact(control, 2) != b'\r\n' or exact(control, size) != payload:
                    raise RuntimeError('Trojan reply payload mismatch')
        else:
            if kind == 'uot':
                directory = root / f'bridge-{serial}'
                directory.mkdir()
                front = stack.enter_context(proxy_client(directory, {
                    'type': 'shadowsocks', 'server': '127.0.0.1', 'server_port': front,
                    'method': '2022-blake3-aes-128-gcm',
                    'password': base64.b64encode(bytes(range(16))).decode(),
                    'udp_over_tcp': {'enabled': True, 'version': 2}}))
            control = stack.enter_context(connect(front))
            control.settimeout(3)
            udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            udp.bind(('127.0.0.1', 0)); udp.settimeout(3)
            control.sendall(b'\x05\x01\x00')
            if exact(control, 2) != b'\x05\x00':
                raise RuntimeError('SOCKS greeting')
            control.sendall(b'\x05\x03\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', udp.getsockname()[1]))
            reply = exact(control, 10)
            if reply[:4] != b'\x05\x00\x00\x01':
                raise RuntimeError('SOCKS association')
            host = socket.inet_ntoa(reply[4:8])
            relay = ('127.0.0.1' if host == '0.0.0.0' else host, int.from_bytes(reply[8:10], 'big'))

            def send(target, payload):
                udp.sendto(b'\0\0\0' + address(target) + payload, relay)

            def receive(target, payload):
                received, _ = udp.recvfrom(65535)
                if received != b'\0\0\0' + address(target) + payload:
                    raise RuntimeError(f'{kind} reply source/payload mismatch: {received!r}')
        yield send, receive, control


def configure(root, fronts, upstream, workers):
    key = base64.b64encode(bytes(range(16))).decode()
    (root / 'ss-key').write_text(key); (root / 'ss-key').chmod(0o600)
    (root / 'password').write_text('secret'); (root / 'password').chmod(0o600)
    (root / 'second.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
    inbounds = {
        'socks': f'socks5 "socks" {{ listen host="127.0.0.1" port={fronts.get("socks", 1)}; authentication "none"; }}',
        'uot': f'shadowsocks "uot" {{ listen host="127.0.0.1" port={fronts.get("uot", 1)}; method "2022-blake3-aes-128-gcm"; key-file "{root / "ss-key"}"; }}',
        'trojan': f'''trojan "trojan" {{ listen host="127.0.0.1" port={fronts.get('trojan', 1)};
 authentication {{ user "bob" password-file="{root / 'password'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'tls-key'}"; }} }}''',
    }
    outbounds = '\n'.join(f'''outbound "{tag}" type="shadowsocks" {{
 server host="127.0.0.1" port={upstream}; method "2022-blake3-aes-128-gcm";
 key-file "{root / 'ss-key'}"; udp-over-tcp "v2"; }}''' for tag in ('first', 'second'))
    config = root / 'nexus.kdl'
    config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{ {'; '.join(inbounds[kind] for kind in fronts)}; }}
outbound "direct" type="direct"
{outbounds}
routing {{ rulesets {{ "second" path="second.kdl" format="kdl"; }};
 rules {{ - kind="rule-set" value="second" outbound="second"; }}; final "first"; }}
''')
    box = root / 'upstream.json'
    box.write_text(json.dumps({'log': {'level': 'warn'}, 'inbounds': [{
        'type': 'shadowsocks', 'listen': '127.0.0.1', 'listen_port': upstream,
        'method': '2022-blake3-aes-128-gcm', 'password': key}], 'outbounds': [{'type': 'direct'}]}))
    return config, box


def exercise(binary, kinds, workers):
    revision = '824dbcfb4dd0a95921840b1737b950cde590241e'
    if f'Revision: {revision}' not in subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError('unexpected sing-box revision')
    with tempfile.TemporaryDirectory(prefix='nexus-lazy-readers-') as temporary, contextlib.ExitStack() as sockets:
        root = Path(temporary)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'tls-key'),
                        '-out', str(root / 'cert'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-days', '1'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root / 'tls-key').chmod(0o600)
        origins = []
        for host in ('127.0.0.1', '127.0.0.2'):
            origin = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            origin.bind((host, 0)); origin.settimeout(3); origins.append(origin)
        fronts = {}
        while len(fronts) < len(kinds):
            port = free_port()
            if port not in fronts.values():
                fronts[kinds[len(fronts)]] = port
        upstream = free_port()
        while upstream in fronts.values():
            upstream = free_port()
        config, box = configure(root, fronts, upstream, workers)
        with running(['sing-box', 'run', '-c', box], upstream, root / 'upstream.log'), \
                nexus_process(str(binary), str(config), len(fronts)) as process:
            with contextlib.ExitStack() as active:
                for round_number in range(2):
                    for kind, front in fronts.items():
                        manager = packet_client(kind, root, front, f'{round_number}-{kind}')
                        if round_number:
                            send, receive, control = active.enter_context(manager)
                        else:
                            send, receive, control = manager.__enter__()
                        try:
                            peers = []
                            # Each association opens both outbound slots; the
                            # second round of packets reuses their live readers.
                            for turn in range(2):
                                for index, origin in enumerate(origins):
                                    payload = f'{kind}/{round_number}/{turn}/{index}'.encode()
                                    target = origin.getsockname(); send(target, payload)
                                    data, peer = origin.recvfrom(65535)
                                    if data != payload:
                                        raise RuntimeError(f'origin mismatch: {data!r}')
                                    if turn == 0:
                                        peers.append(peer)
                                    elif peer != peers[index]:
                                        raise RuntimeError('slot unexpectedly reconnected during reuse')
                                    origin.sendto(data, peer); receive(target, payload)
                            if peers[0] == peers[1]:
                                raise RuntimeError('two outbounds shared a single UDP transport')
                            if round_number:
                                # Leave each lazy reader waiting for a proxy
                                # reply while keeping all inbound controls open.
                                for index, origin in enumerate(origins):
                                    payload = f'held/{kind}/{index}'.encode(); send(origin.getsockname(), payload)
                                    data, _ = origin.recvfrom(65535)
                                    if data != payload:
                                        raise RuntimeError('active stop did not reach both slots')
                            print(f'{kind}: two slots first reply, reuse and association={round_number} passed', flush=True)
                        finally:
                            if not round_number:
                                manager.__exit__(None, None, None)
                started = time.monotonic(); process.terminate(); process.wait(timeout=5)
                if process.returncode or time.monotonic() - started >= 5:
                    raise RuntimeError('active lazy readers did not stop cleanly')
            print('all requested associations stopped with both proxy readers active', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--transport', choices=('all', 'socks', 'trojan', 'uot'), default='all')
    parser.add_argument('--workers', type=int, choices=(1, 2), default=2)
    args = parser.parse_args()
    exercise(args.binary.resolve(), ('socks', 'trojan', 'uot') if args.transport == 'all' else (args.transport,), args.workers)
