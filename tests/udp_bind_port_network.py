#!/usr/bin/env python3
"""Physical UDP source-port checks; Hy2 evidence stops at an observed Initial."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

REPO = next(parent for parent in Path(__file__).resolve().parents if (parent / 'tests/dns_rule_support.py').is_file())
sys.path.insert(0, str(REPO / 'tests'))
from anytls_proxy_network import CountedRelay, begin, reply
from dns_rule_support import Echo, exact, free_port, nexus_process, proxy_client, udp_client

REVISION = '824dbcfb4dd0a95921840b1737b950cde590241e'
KEY = base64.b64encode(bytes(range(16))).decode()
SOURCE = {socket.AF_INET: '127.0.0.2', socket.AF_INET6: '::1'}
ORIGIN = {socket.AF_INET: '127.0.0.1', socket.AF_INET6: '::1'}
FAMILIES = (socket.AF_INET, socket.AF_INET6)


def different_port(*excluded):
    for _ in range(100):
        port = free_port()
        if port not in excluded:
            return port
    raise RuntimeError('could not select distinct listener port')


@contextmanager
def reserve_port(kind=socket.SOCK_DGRAM):
    with socket.socket(socket.AF_INET6, kind) as reserved:
        reserved.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        reserved.bind(('::', 0))
        if kind == socket.SOCK_STREAM:
            reserved.listen(1)
        yield reserved, reserved.getsockname()[1]


def wire(family, port, payload):
    kind = b'\x01' if family == socket.AF_INET else b'\x04'
    return b'\0\0\0' + kind + socket.inet_pton(family, ORIGIN[family]) + struct.pack('!H', port) + payload


def exchange(client, relay, source_port, families, expected, records, label):
    for family in families:
        with socket.socket(family, socket.SOCK_DGRAM) as origin:
            if family == socket.AF_INET6:
                origin.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            origin.bind((ORIGIN[family], 0)); origin.settimeout(3)
            for payload in (b'', b'source-port-bound'):
                encoded = wire(family, origin.getsockname()[1], payload)
                client.sendto(encoded, relay)
                received, sender = origin.recvfrom(1024)
                if received != payload or sender[:2] != (expected[family], source_port):
                    raise RuntimeError(f'{label}: source/payload mismatch: {sender}, {received!r}')
                origin.sendto(received, sender)
                response, _ = client.recvfrom(1024)
                if response != encoded:
                    raise RuntimeError(f'{label}: reply target or bytes changed')
                records.append({'case': label, 'family': 4 if family == socket.AF_INET else 6,
                                'source': list(sender[:2]), 'size': len(payload), 'reply': True})


def config(front, direct='', node='', inbound=None, ordered=False):
    inbound = inbound or f'inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}'
    final = 'edge' if node else 'direct'
    program = f'tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{ rule action="route" outbound="{final}"; }};' if ordered else ''
    return f'''schema-version 1
role "client"
workers 1
{inbound}
outbound "direct" type="direct" {{ {direct} }}
{node}
routing {{ {program} final "{final}"; }}
'''


def source_fields(families):
    return ' '.join(f'inet{4 if family == socket.AF_INET else 6}-bind-address "{SOURCE[family]}";' for family in families)


def launch(binary, root, label, text):
    path = root / f'{label}.kdl'; path.write_text(text)
    return nexus_process(binary, path)


def direct_cases(binary, root, records):
    with reserve_port() as (reservation, port):
        front = different_port(port)
        with launch(binary, root, 'direct-busy', config(front, f'udp-bind-port {port};')):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin, udp_client(front) as (client, relay):
                origin.bind(('127.0.0.1', 0)); origin.settimeout(.3)
                client.sendto(wire(socket.AF_INET, origin.getsockname()[1], b'blocked'), relay)
                try:
                    origin.recvfrom(1024)
                except socket.timeout:
                    records.append({'case': 'direct-busy', 'rejected_before_data': True})
                else:
                    raise RuntimeError('busy source port silently fell back to an ephemeral port')
            reservation.close(); time.sleep(.05)
            with udp_client(front) as (client, relay):
                exchange(client, relay, port, FAMILIES, ORIGIN, records, 'direct-recovered-dual-wildcard')
    for families in ((socket.AF_INET,), (socket.AF_INET6,), FAMILIES):
        with reserve_port() as (reservation, port):
            front = different_port(port)
            label = 'direct-explicit-' + ''.join('4' if f == socket.AF_INET else '6' for f in families)
            fields = f'udp-bind-port {port}; {source_fields(families)}'
            with launch(binary, root, label, config(front, fields, ordered=True)), udp_client(front) as (client, relay):
                reservation.close()
                exchange(client, relay, port, families, SOURCE, records, label)
    for bound_family in FAMILIES:
        expected = ORIGIN | {bound_family: SOURCE[bound_family]}
        for ordered, order in ((False, FAMILIES), (True, FAMILIES[::-1])):
            with reserve_port() as (reservation, port):
                front = different_port(port)
                bound = '4' if bound_family == socket.AF_INET else '6'
                first = '4' if order[0] == socket.AF_INET else '6'
                label = f'direct-source-{bound}-first-{first}'
                fields = f'udp-bind-port {port}; {source_fields((bound_family,))}'
                with launch(binary, root, label, config(front, fields, ordered=ordered)), udp_client(front) as (client, relay):
                    reservation.close()
                    exchange(client, relay, port, order, expected, records, label)
    print('direct: fixed-port reuse across both families, source addresses, busy bind and recovery passed', flush=True)


def ss_inbound(root, port):
    return f'''inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={port};
 method "2022-blake3-aes-128-gcm"; key-file "{root / 'psk'}"; }}'''


def ss_cases(binary, root, records):
    for uot in (False, True):
        with reserve_port() as (reservation, port):
            inbound_port = different_port(port)
            label = 'ss-uot-stream-direct' if uot else 'ss-native-direct'
            fields = f'udp-bind-port {port}; {source_fields(FAMILIES)}'
            text = config(inbound_port, fields, inbound=ss_inbound(root, inbound_port), ordered=True)
            outbound = {'type': 'shadowsocks', 'server': '127.0.0.1', 'server_port': inbound_port,
                        'method': '2022-blake3-aes-128-gcm', 'password': KEY}
            if uot:
                outbound['udp_over_tcp'] = {'enabled': True, 'version': 2}
            with launch(binary, root, label, text), proxy_client(root, outbound) as front, udp_client(front) as (client, relay):
                reservation.close()
                exchange(client, relay, port, FAMILIES, SOURCE, records, label)
        print(label + ': observed both source addresses/ports, empty datagrams and replies', flush=True)


class SourceRelay(CountedRelay):
    def __init__(self, target):
        super().__init__(target); self.sources = []

    def peer(self, incoming):
        self.sources.append(incoming.getpeername()[:2])
        super().peer(incoming)


def tcp_cases(binary, root, records):
    with reserve_port(socket.SOCK_STREAM) as (_, port):
        server = different_port(port)
        server_text = config(server, inbound=ss_inbound(root, server))
        with launch(binary, root, 'tcp-ss-server', server_text), SourceRelay(server) as relay, Echo() as origin:
            for inherited in (False, True):
                label = 'tcp-ss-direct-detour' if inherited else 'tcp-ss-own'
                front = different_port(port, server, relay.port, origin.port)
                fields = '' if inherited else f'udp-bind-port {port};'
                detour = 'detour "direct";' if inherited else ''
                node = f'''outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={relay.port};
 method "2022-blake3-aes-128-gcm"; key-file "{root / 'psk'}"; {fields} {detour} }}'''
                text = config(front, f'udp-bind-port {port};' if inherited else '', node)
                before = len(relay.sources)
                with launch(binary, root, label, text), begin(front, origin.port) as client:
                    reply(client); client.sendall(b'tcp-must-not-bind-udp-port')
                    if exact(client, len(b'tcp-must-not-bind-udp-port')) != b'tcp-must-not-bind-udp-port':
                        raise RuntimeError(label + ': TCP echo mismatch')
                observed = relay.sources[before:]
                if len(observed) != 1 or observed[0][1] == port:
                    raise RuntimeError(f'{label}: wrong physical TCP source {observed}')
                records.append({'case': label, 'occupied_tcp_port': port, 'physical_sources': observed,
                                'tcp_echo': True, 'udp_port_not_used_for_tcp': True})
        print('TCP SS physical transport: own and direct-detour UDP port never binds occupied TCP port', flush=True)


def certificate(root):
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                    '-keyout', str(root / 'key'), '-out', str(root / 'cert')], check=True, capture_output=True)


def hy2_cases(binary, root, records):
    certificate(root)
    for family in FAMILIES:
        for inherited in (False, True):
            with reserve_port() as (reservation, port), socket.socket(family, socket.SOCK_DGRAM) as peer:
                peer.bind((ORIGIN[family], 0)); peer.settimeout(5)
                target = peer.getsockname()[1]
                front = different_port(port, target)
                label = f'hy2-initial-v{4 if family == socket.AF_INET else 6}-' + ('direct-detour' if inherited else 'own')
                binding = f'udp-bind-port {port}; {source_fields((family,))}'
                node = f'''outbound "edge" type="hysteria2" {{ server host="{ORIGIN[family]}" port={target};
 authentication {{ password-file "{root / 'password'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
 {'detour "direct";' if inherited else binding}
}}'''
                text = config(front, binding if inherited else '', node)
                with launch(binary, root, label, text) as process:
                    reservation.close()
                    with begin(front, 9) as client:
                        datagram, sender = peer.recvfrom(65535)
                        if sender[:2] != (SOURCE[family], port) or len(datagram) < 1200 or \
                                datagram[0] & 0xf0 != 0xc0 or datagram[1:5] != b'\0\0\0\1':
                            raise RuntimeError(f'{label}: unexpected Initial/source {sender} {datagram[:5].hex()} size={len(datagram)}')
                        start = time.monotonic(); process.terminate(); stdout, stderr = process.communicate(timeout=5)
                        if process.returncode:
                            raise RuntimeError(f'{label}: stop failed: {process.returncode} {stdout!r} {stderr!r}')
                        client.settimeout(1)
                        try:
                            remaining = client.recv(32)
                        except ConnectionResetError:
                            remaining = b''
                        if remaining[:2] == b'\x05\x00':
                            raise RuntimeError(label + ': pending SOCKS unexpectedly accepted during stop')
                        with socket.socket(family, socket.SOCK_DGRAM) as released:
                            if family == socket.AF_INET6:
                                released.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                            released.bind((SOURCE[family], port))
                        records.append({'case': label, 'source': list(sender[:2]), 'initial_size': len(datagram),
                                        'stop_seconds': time.monotonic() - start, 'source_port_released': True,
                                        'handshake_completed': False})
                print(label + ': source observed on QUIC Initial; hanging handshake stopped and port released', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--cases', nargs='+', choices=('direct', 'ss', 'tcp', 'hy2'), default=['direct', 'ss', 'tcp', 'hy2'])
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(); binary = str(args.binary.resolve(strict=True)); records = []
    if 'ss' in args.cases:
        version = subprocess.check_output(['sing-box', 'version'], text=True)
        if REVISION not in version:
            raise RuntimeError('unexpected sing-box peer revision: ' + version)
    else:
        version = None
    report = {'binary': binary, 'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'sing_box_version': version,
              'cases': records}
    try:
        with tempfile.TemporaryDirectory(prefix='nexus-udp-bind-port-') as directory:
            root = Path(directory)
            for name, content in (('psk', KEY), ('password', 'source-port-test')):
                path = root / name; path.write_text(content); path.chmod(0o600)
            for name in dict.fromkeys(args.cases):
                globals()[name + '_cases'](binary, root, records)
        report['exit'] = 0
    except Exception as error:
        report.update(exit=1, error=repr(error)); raise
    finally:
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
