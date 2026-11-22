"""SOCKS UDP: interleaved authenticated Initial flows and persistent unknown."""
import argparse
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from dns_rule_support import free_port, nexus_process, question, udp_client


def vectors(fixture, mode, count):
    data = subprocess.run([fixture, mode], check=True, capture_output=True).stdout
    packets = []
    for _ in range(count):
        if len(data) < 2:
            raise RuntimeError(f'{mode}: missing packet length')
        size = int.from_bytes(data[:2], 'big')
        if not size or len(data) < size + 2:
            raise RuntimeError(f'{mode}: truncated packet')
        packets.append(data[2:size + 2])
        data = data[size + 2:]
    if data:
        raise RuntimeError(f'{mode}: unexpected trailing data')
    return packets


def header(origin):
    return b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', origin.getsockname()[1])


def receive(origin, expected, description):
    origin.settimeout(3)
    actual, _ = origin.recvfrom(65535)
    if actual != expected:
        raise RuntimeError(f'{description}: expected {len(expected)} bytes, got {len(actual)}')


def quiet(origin, description, timeout=.12):
    origin.settimeout(timeout)
    try:
        actual, _ = origin.recvfrom(65535)
    except TimeoutError:
        return
    raise RuntimeError(f'{description}: forwarded {len(actual)} bytes')


def configure(root, front, a, b, unknown='reject', early=False, repeated=False):
    rules = []
    if early:
        # Remembered results belong to this packet's sniff action. If a queued
        # result leaks into its initial input, these rules reject it too early.
        rules.extend(f'rule action="reject" rule-set="{name}" domain-source="sniffed"'
                     for name in ('a', 'b'))
    rules.append('rule action="sniff"')
    if repeated:
        rules.append('rule action="sniff"')
    for name, action in (('a', a), ('b', b)):
        outbound = ' outbound="direct"' if action == 'route' else ''
        rules.append(f'rule action="{action}" rule-set="{name}" domain-source="sniffed"{outbound}')
    rules.append('rule action="route" outbound="direct"' if unknown == 'route' else 'rule action="reject"')
    path = root / 'config.kdl'
    path.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
routing {{
 rule-set "a" path="a.kdl" format="kdl"
 rule-set "b" path="b.kdl" format="kdl"
 tcp-program sniff-timeout-ms=1000 unknown="skip" udp=#true {{ {'; '.join(rules)}; }}
 default-outbound "direct"
}}
''')
    return path


def interleaved(binary, root, front, packets, origin, other, same_target, mode):
    a1, b1, b2, a2 = packets
    target_b = origin if same_target else other
    a, b = ('route', 'route') if mode == 'both' else ('route', 'reject') if mode == 'a' else ('reject', 'route')
    # Both allowed requires known SNI on every packet. Mixed routing lets
    # unknown through, exposing a rejected flow mistakenly replayed unknown.
    config = configure(root, front, a, b, unknown='reject' if mode == 'both' else 'route', early=True)
    with nexus_process(binary, str(config)), udp_client(front) as (client, relay):
        client.sendto(header(origin) + a1, relay)
        quiet(origin, 'A1 escaped before its missing CRYPTO fragment', .06)
        for target, packet in ((target_b, b1), (target_b, b2), (origin, a2)):
            client.sendto(header(target) + packet, relay)
        if same_target:
            expected = [p for p, action in ((a1, a), (b1, b), (b2, b), (a2, a)) if action == 'route']
            for packet in expected:
                receive(origin, packet, f'{mode}: combined flow FIFO/SNI decision')
            quiet(origin, 'rejected or duplicate packet reached the shared target')
        else:
            for target, action, flow in ((origin, a, (a1, a2)), (other, b, (b1, b2))):
                if action == 'route':
                    for packet in flow:
                        receive(target, packet, f'{mode}: per-target FIFO/SNI decision')
                quiet(target, 'rejected or duplicate packet reached a separate target')
    print(f'SOCKS A1/B1/B2/A2: {"same" if same_target else "different"} target, allowed={mode}', flush=True)


def late_fragment(binary, root, front, packets, origin):
    a1, b1, b2, a2 = packets
    config = configure(root, front, 'route', 'route', early=True)
    with nexus_process(binary, str(config)), udp_client(front) as (client, relay):
        for packet in (a1, b1, a2):
            client.sendto(header(origin) + packet, relay)
        receive(origin, a1, 'A did not complete while B was incomplete')
        quiet(origin, 'B1 or queued A2 overtook the incomplete FIFO head', .06)
        client.sendto(header(origin) + b2, relay)
        for packet in (b1, a2, b2):
            receive(origin, packet, 'replayed B1 could not collect its later B2')
        quiet(origin, 'late-fragment replay duplicated a packet')
    print('SOCKS replayed queue head collects newly received fragments in FIFO order', flush=True)


def conflict_unknown(binary, root, front, packets, origin):
    first, complete = packets
    config = configure(root, front, 'reject', 'reject', unknown='route', repeated=True)
    with nexus_process(binary, str(config)), udp_client(front) as (client, relay):
        # Control: the authenticated complete packet has visible example.com
        # when no earlier fragment conflicts with its ClientHello.random.
        client.sendto(header(origin) + complete, relay)
        quiet(origin, 'standalone complete Hello was not recognized and rejected')
        client.sendto(header(origin) + first, relay)
        quiet(origin, 'first conflict fragment escaped before completion', .06)
        client.sendto(header(origin) + complete, relay)
        receive(origin, first, 'conflicting flow failed unknown fallback')
        receive(origin, complete, 'replayed conflicting complete Hello recovered forbidden SNI')
        quiet(origin, 'conflicting-flow replay duplicated a packet')
    print('SOCKS authenticated overlap conflict remains unknown through replay and repeated sniff', flush=True)


class ControlledDns:
    def __enter__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.count = 0
        return self

    def __exit__(self, *_):
        self.socket.close()

    def query(self):
        self.socket.settimeout(3)
        wire, peer = self.socket.recvfrom(4096)
        name, kind, end = question(wire)
        if name != 'cursor.test' or kind != 1:
            raise RuntimeError(f'unexpected explicit resolution {name}/{kind}')
        self.count += 1
        return wire, peer, end

    def answer(self, request, ip='127.0.0.1'):
        wire, peer, end = request
        response = wire[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + wire[12:end]
        response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(ip)
        self.socket.sendto(response, peer)


def cursor_dns(binary, root, front, packets, origin):
    first, _, _, second = packets
    raw = b'cursor.test'
    target = b'\0\0\0\x03' + bytes([len(raw)]) + raw + struct.pack('!H', origin.getsockname()[1])
    with ControlledDns() as dns:
        for complete in (True, False):
            config = root / 'config.kdl'
            terminal = ('rule action="route" rule-set="a" domain-source="sniffed" outbound="direct"; rule action="reject";'
                        if complete else 'rule action="reject" rule-set="a" domain-source="sniffed"; rule action="route" outbound="direct";')
            config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
dns {{ servers {{ udp "resolver" host="127.0.0.1" port={dns.socket.getsockname()[1]}; }}; final "resolver"; strategy "ipv4_only"; disable-cache #true; }}
routing {{ rule-set "a" path="a.kdl" format="kdl"; tcp-program sniff-timeout-ms=1000 unknown="skip" udp=#true {{
 rule action="resolve"
 rule action="reject" rule-set="a" domain-source="sniffed"
 rule action="sniff"
 rule action="resolve"
 rule action="sniff"
 {terminal}
}}; default-outbound "direct"; }}
''')
            before = dns.count
            with nexus_process(binary, str(config)), udp_client(front) as (client, relay):
                client.sendto(target + first, relay)
                initial = dns.query()
                quiet(origin, 'first packet escaped while initial DNS was held', .04)
                dns.answer(initial, '127.0.0.2')
                resumed = time.monotonic()
                if complete:
                    quiet(dns.socket, 'second resolve ran before sniff could finish', .06)
                    client.sendto(target + second, relay)
                following = dns.query()
                if not complete and time.monotonic() - resumed < .75:
                    raise RuntimeError('unknown first sniff did not wait for its timeout')
                quiet(origin, 'routing escaped while the second explicit resolve was held', .04)
                dns.answer(following)
                # Receiving A1 now proves the earlier resolve was not replayed;
                # only A2 is allowed to begin the next two DNS transactions.
                origin.settimeout(.4 if not complete else 3)
                actual, _ = origin.recvfrom(65535)
                if actual != first:
                    raise RuntimeError('cursor restart, second sniff wait, or first-packet FIFO failure')
                if complete:
                    dns.answer(dns.query(), '127.0.0.2')
                    dns.answer(dns.query())
                    receive(origin, second, 'queued fragment lost its own resolve/sniff actions')
                expected = 4 if complete else 2
                if dns.count - before != expected:
                    raise RuntimeError(f'explicit resolve count {dns.count - before}, expected {expected}')
                quiet(dns.socket, 'cursor repeated an earlier explicit resolve')
                quiet(origin, 'cursor replay duplicated a packet')
            print(f'SOCKS resolve/sniff/resolve/sniff: {"fragmented known" if complete else "timeout unknown without second wait"}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('fixture', help='quic-sniff with --interleaved/--conflicting-complete')
    parser.add_argument('--case', choices=('interleaved', 'late', 'conflict', 'cursor', 'all'), default='all')
    args = parser.parse_args()
    packets = vectors(args.fixture, '--interleaved', 4)
    conflicts = vectors(args.fixture, '--conflicting-complete', 2)
    with tempfile.TemporaryDirectory() as directory, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
        root = Path(directory)
        for name, domain in (('a', 'example.com'), ('b', 'example.net')):
            (root / f'{name}.kdl').write_text(
                f'schema-version 2\nkind "predicate"\nrule type="domain" value="{domain}"\n')
        origin.bind(('127.0.0.1', 0))
        other.bind(('127.0.0.1', 0))
        front = free_port()
        if args.case in ('interleaved', 'all'):
            for same_target in (True, False):
                for mode in ('both', 'a', 'b'):
                    interleaved(args.binary, root, front, packets, origin, other, same_target, mode)
        if args.case in ('late', 'all'):
            late_fragment(args.binary, root, front, packets, origin)
        if args.case in ('conflict', 'all'):
            conflict_unknown(args.binary, root, front, conflicts, origin)
        if args.case in ('cursor', 'all'):
            cursor_dns(args.binary, root, front, packets, origin)


if __name__ == '__main__':
    main()
