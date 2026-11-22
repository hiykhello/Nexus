"""SS native UDP QUIC reassembly, ordered replay and DNS/stop ownership."""
import argparse
import base64
import contextlib
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from dns_rule_support import DnsPeer, free_port, nexus_process, ss_client


def fragments(fixture):
    data = subprocess.run([fixture, '--fragments'], check=True, capture_output=True).stdout
    packets = []
    for _ in range(2):
        if len(data) < 2:
            raise RuntimeError('fragment fixture omitted its length')
        size = int.from_bytes(data[:2], 'big')
        if not size or len(data) < size + 2:
            raise RuntimeError('invalid fragment fixture length')
        packets.append(data[2:size + 2])
        data = data[size + 2:]
    if data:
        raise RuntimeError('trailing fragment fixture data')
    return packets


def header(sock, name=None):
    address = b'\x01' + socket.inet_aton('127.0.0.1')
    if name:
        raw = name.encode('ascii')
        address = b'\x03' + bytes([len(raw)]) + raw
    return b'\x00\x00\x00' + address + struct.pack('!H', sock.getsockname()[1])


def quiet(sock, seconds, reason):
    sock.settimeout(seconds)
    try:
        packet, _ = sock.recvfrom(65535)
    except TimeoutError:
        return
    raise RuntimeError(f'{reason}: forwarded {len(packet)} bytes')


def receive(sock, expected, reason, timeout=3):
    sock.settimeout(timeout)
    packet, peer = sock.recvfrom(65535)
    if packet != expected:
        raise RuntimeError(f'{reason}: expected {len(expected)} bytes, got {len(packet)}')
    return peer


class Scenario:
    def __init__(self, root, binary, dns, protocol=False):
        self.root, self.binary, self.dns = root, binary, dns
        self.key = bytes(range(16))
        (root / 'key').write_text(base64.b64encode(self.key).decode())
        (root / 'key').chmod(0o600)
        predicate = 'type="protocol" value="quic"' if protocol else 'type="domain" value="example.com"'
        (root / 'rule.kdl').write_text(f'schema-version 2\nkind "predicate"\nrule {predicate}\n')
        self.front = free_port()

    def configure(self, allow=False, resolve=None, timeout=500):
        action = 'route' if allow else 'reject'
        outbound = ' outbound="direct"' if allow else ''
        rules = ['rule action="sniff"',
                 f'rule action="{action}" rule-set="name" domain-source="sniffed"{outbound}']
        if resolve == 'before':
            rules.insert(0, 'rule action="resolve"')
        elif resolve == 'after':
            # Place resolution after sniff but before the terminal match, so
            # an allowed match also exercises the suspended DNS continuation.
            rules.insert(1, 'rule action="resolve"')
        rules.append('rule action="route" outbound="direct"')
        path = self.root / 'config.kdl'
        path.write_text(f'''schema-version 1
role "server"
workers 2
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={self.front}; method "2022-blake3-aes-128-gcm"; key-file "{self.root / 'key'}"; }}
outbound "direct" type="direct"
dns {{ servers {{ udp "resolver" host="127.0.0.1" port={self.dns.port}; }}; final "resolver"; strategy "ipv4_only"; disable-cache #true; }}
routing {{ rule-set "name" path="rule.kdl" format="kdl"; tcp-program sniff-timeout-ms={timeout} unknown="skip" udp=#true {{ {'; '.join(rules)}; }}; default-outbound "direct"; }}
''')
        return path

    @contextlib.contextmanager
    def run(self, **options):
        path = self.configure(**options)
        with nexus_process(self.binary, str(path)) as process, \
                ss_client(self.root, self.front, self.key) as connection:
            yield process, connection


def rejected_and_timeout(scenario, origin, other, first, second, resolve=None):
    name = f'{resolve}.test' if resolve else None
    target = header(origin, name)
    with scenario.run(resolve=resolve) as (_, (client, relay)):
        client.sendto(target + first, relay)
        quiet(origin, .08, 'first fragment escaped before sniff completed')
        if name and resolve == 'after' and scenario.dns.count(name, 1):
            raise RuntimeError('resolve after sniff ran before the fragment arrived')
        # This complementary fragment has another destination. It must not
        # supply the first flow's missing CRYPTO bytes or inherit its name.
        client.sendto(header(other) + second, relay)
        client.sendto(target + second, relay)
        receive(other, second, 'isolated target did not fall back unchanged')
        quiet(origin, .12, 'matched SNI rejection leaked a fragment')
        if name and not scenario.dns.count(name, 1):
            raise RuntimeError(f'{resolve}: explicit DNS action was not executed')
        started = time.monotonic()
        client.sendto(target + first, relay)
        peer = receive(origin, first, 'incomplete flow did not replay on timeout')
        if time.monotonic() - started < .35:
            raise RuntimeError('sniff timeout was not respected')
        origin.sendto(first, peer)
        receive(client, header(origin) + first, 'timeout reply changed the payload')
    print(f'SS native fragmented rejection, target isolation and timeout: {resolve or "numeric"}', flush=True)


def accepted_fifo(scenario, origin, other, first, second, resolve=None):
    name = f'allowed-{resolve}.test' if resolve else None
    target = header(origin, name)
    marker = b'same-target-non-initial'
    with scenario.run(allow=True, resolve=resolve) as (_, (client, relay)):
        client.sendto(target + first, relay)
        quiet(origin, .08, 'allowed first fragment escaped before classification')
        client.sendto(target + marker, relay)
        client.sendto(header(other) + b'other-target', relay)
        receive(other, b'other-target', 'unrelated target was blocked by sniff')
        quiet(origin, .06, 'same-target packet overtook the first fragment')
        client.sendto(target + second, relay)
        for expected in (first, marker, second):
            receive(origin, expected, 'accepted flow did not replay FIFO')
        if name and not scenario.dns.count(name, 1):
            raise RuntimeError(f'{resolve}: allowed domain flow skipped DNS')
    print(f'SS native allowed FIFO including non-Initial: {resolve or "numeric"}', flush=True)


def sessions_and_stop(scenario, origin, other, first, second):
    second_root = scenario.root / 'second-client'
    second_root.mkdir()
    with scenario.run() as (_, (one, relay_one)), \
            ss_client(second_root, scenario.front, scenario.key) as (two, relay_two):
        one.sendto(header(origin) + first, relay_one)
        two.sendto(header(origin) + second, relay_two)
        quiet(origin, .15, 'separate sessions shared an incomplete probe')
        origin.settimeout(3)
        packets = [origin.recvfrom(65535)[0] for _ in range(2)]
        if sorted(packets) != sorted([first, second]):
            raise RuntimeError('separate sessions did not each replay their own packet')
    with scenario.run(timeout=2000) as (process, (client, relay)):
        client.sendto(header(origin) + first, relay)
        client.sendto(header(other) + b'stop-barrier', relay)
        receive(other, b'stop-barrier', 'stop barrier was not processed')
        quiet(origin, .08, 'pending sniff unexpectedly completed')
        started = time.monotonic()
        process.terminate()
        process.wait(timeout=3)
        if process.returncode or time.monotonic() - started >= 2:
            raise RuntimeError('pending sniff did not cancel promptly at shutdown')
        quiet(origin, .1, 'shutdown replayed a canceled token')
    print('SS native independent sessions and pending-sniff shutdown passed', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('fixture', help='quic-sniff executable supporting --fragments')
    parser.add_argument('--case', choices=('numeric', 'dns', 'lifecycle', 'all'), default='all')
    parser.add_argument("--protocol", action="store_true")
    args = parser.parse_args()
    revision = '824dbcfb4dd0a95921840b1737b950cde590241e'
    version = subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout
    if f'Revision: {revision}' not in version:
        raise RuntimeError('unexpected sing-box revision')
    first, second = fragments(args.fixture)
    with tempfile.TemporaryDirectory() as directory, DnsPeer() as dns, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
        origin.bind(('127.0.0.1', 0))
        other.bind(('127.0.0.1', 0))
        scenario = Scenario(Path(directory), args.binary, dns, args.protocol)
        modes = [None] if args.case == 'numeric' else ['before', 'after'] if args.case == 'dns' else \
            [None, 'before', 'after'] if args.case == 'all' else []
        for mode in modes:
            rejected_and_timeout(scenario, origin, other, first, second, mode)
            accepted_fifo(scenario, origin, other, first, second, mode)
        if args.case in ('all', 'lifecycle'):
            sessions_and_stop(scenario, origin, other, first, second)


if __name__ == '__main__':
    main()
