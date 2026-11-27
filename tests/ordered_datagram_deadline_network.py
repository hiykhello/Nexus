"""Original ten-second UDP deadlines across sniff queues, DNS and TLS dialing.

The selected transports run together in each ~11-second window. This checks
ordered SOCKS, Trojan UDP and SS UoT queues, not decoder saturation, XUDP ID
rotation or blocked application writes. The tunnel case observes a real TCP
peer withholding its TLS flight; an expired tunnel may close its session.
"""
import argparse
import base64
import contextlib
import hashlib
import select
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from dns_rule_support import free_port, nexus_process, proxy_client, question, udp_client
from ordered_quic_ss_fragment_network import fragments


TRANSPORTS = ('socks', 'trojan', 'uot')
RELEASE = 6.5
DNS_REPLY = 10.8
LATEST_CLOSE = 11.5


def address(name, port):
    encoded = b'\x01' + socket.inet_aton('127.0.0.1')
    if name:
        raw = name.encode('ascii')
        encoded = b'\x03' + bytes([len(raw)]) + raw
    return encoded + struct.pack('!H', port)


@contextlib.contextmanager
def client(kind, root, front):
    with contextlib.ExitStack() as stack:
        if kind == 'trojan':
            context = ssl.create_default_context(cafile=str(root / 'cert'))
            peer = stack.enter_context(context.wrap_socket(
                socket.create_connection(('127.0.0.1', front), timeout=5), server_hostname='localhost'))
            peer.sendall(hashlib.sha224(b'secret').hexdigest().encode() +
                         b'\r\n\x03\x01\x00\x00\x00\x00\x00\x00\r\n')

            def send(name, port, payload):
                peer.sendall(address(name, port) + struct.pack('!H', len(payload)) + b'\r\n' + payload)
        else:
            if kind == 'uot':
                directory = root / 'sing-box'
                directory.mkdir(exist_ok=True)
                outbound = {'type': 'shadowsocks', 'server': '127.0.0.1', 'server_port': front,
                            'method': '2022-blake3-aes-128-gcm',
                            'password': base64.b64encode(bytes(range(16))).decode(),
                            'udp_over_tcp': {'enabled': True, 'version': 2}}
                front = stack.enter_context(proxy_client(directory, outbound))
            peer, relay = stack.enter_context(udp_client(front))

            def send(name, port, payload):
                peer.sendto(b'\0\0\0' + address(name, port) + payload, relay)
        yield send


def bind_socket(stack, stream=False):
    sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM if stream else socket.SOCK_DGRAM))
    sock.bind(('127.0.0.1', 0))
    if stream:
        sock.listen(4)
    sock.settimeout(3)
    return sock


def no_activity_until(until, sockets, description):
    remaining = until - time.monotonic()
    if remaining > 0 and select.select(sockets, [], [], remaining)[0]:
        raise RuntimeError(description)


def receive(origin, expected, description):
    packet, _ = origin.recvfrom(65535)
    if packet != expected:
        raise RuntimeError(f'{description}: expected {expected[:20]!r}, got {packet[:20]!r}')


def configure(root, kinds, fronts, dns, upstreams):
    inbounds, extra, rules = [], [], ['rule action="sniff"',
        'rule action="route" rule-set="hello" domain-source="sniffed" outbound="direct"']
    files = ['hello path="hello.kdl" format="kdl"']
    for kind in kinds:
        listen = f'listen host="127.0.0.1" port={fronts[kind]};'
        if kind == 'socks':
            inbounds.append(f'socks5 "{kind}" {{ {listen} authentication "none"; }}')
        elif kind == 'trojan':
            inbounds.append(f'''trojan "{kind}" {{ {listen}
 authentication {{ user "bob" password-file="{root / 'password'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'tls-key'}"; }}
}}''')
        else:
            inbounds.append(f'shadowsocks "{kind}" {{ {listen} method "2022-blake3-aes-128-gcm"; key-file "{root / "ss-key"}"; }}')
        if upstreams:
            tag = f'edge-{kind}'
            (root / f'{tag}.kdl').write_text(f'schema-version 2\nkind "predicate"\nrule type="inbound" value="{kind}"\n')
            files.append(f'"{tag}" path="{tag}.kdl" format="kdl"')
            rules.append(f'rule action="route" rule-set="{tag}" outbound="{tag}"')
            extra.append(f'''outbound "{tag}" type="vless" {{
 server host="127.0.0.1" port={upstreams[kind].getsockname()[1]}; connect-timeout-ms 20000
 authentication {{ uuid-file "{root / 'uuid'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}''')
    rules.append('rule action="resolve"')
    rules.append('rule action="route" outbound="direct"')
    path = root / 'config.kdl'
    path.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ {'; '.join(inbounds)}; }}
outbound "direct" type="direct" {{ connect-timeout-ms 20000; }}
{chr(10).join(extra)}
dns {{ servers {{ udp "resolver" host="127.0.0.1" port={dns.getsockname()[1]}; }}; final "resolver"; strategy "ipv4_only"; disable-cache #true; }}
routing {{ rulesets {{ {'; '.join(files)}; }}; tcp-program sniff-timeout-ms=9000 unknown="skip" udp=#true {{ {'; '.join(rules)}; }}; final "direct"; }}
''')
    return path


def run_case(binary, root, kinds, first, second, tunnel):
    with contextlib.ExitStack() as stack:
        dns = bind_socket(stack)
        origins = {kind: bind_socket(stack) for kind in kinds}
        upstreams = {kind: bind_socket(stack, True) for kind in kinds} if tunnel else {}
        fronts = {}
        for kind in kinds:
            fronts[kind] = free_port()
            while fronts[kind] in [value for key, value in fronts.items() if key != kind]:
                fronts[kind] = free_port()
        config = configure(root, kinds, fronts, dns, upstreams)
        stack.enter_context(nexus_process(binary, str(config), listeners=len(kinds)))
        senders = {kind: stack.enter_context(client(kind, root, fronts[kind])) for kind in kinds}
        start = time.monotonic()
        for kind, send in senders.items():
            port = origins[kind].getsockname()[1]
            send(None, port, first)
            send(None if tunnel else f'queued-{kind}.test', port, f'queued-{kind}'.encode())
        # The incomplete head keeps the second packet in the authenticated
        # queue. Early DNS/dial activity or direct forwarding is a test failure.
        no_activity_until(start + RELEASE, [dns, *origins.values(), *upstreams.values()],
                          'queued work or incomplete head escaped before A2')
        for kind, send in senders.items():
            send(None, origins[kind].getsockname()[1], second)
        for kind in kinds:
            receive(origins[kind], first, f'{kind}: first fragment did not finish')
        if tunnel:
            check_tunnels(stack, upstreams, start)
        else:
            check_dns(dns, origins, senders, second, start)
    print(f'{"queued TLS dial" if tunnel else "queued DNS"}: original deadline held for {", ".join(kinds)}', flush=True)


def check_dns(dns, origins, senders, second, start):
    pending = {}
    until = start + RELEASE + 2
    while len(pending) < len(origins):
        dns.settimeout(max(.01, until - time.monotonic()))
        packet, peer = dns.recvfrom(4096)
        name, kind, end = question(packet)
        if kind != 1 or name not in {f'queued-{transport}.test' for transport in origins}:
            raise RuntimeError(f'unexpected queued lookup {name}/{kind}')
        pending[name] = (packet, peer, end)
    remaining = start + DNS_REPLY - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)
    # The response arrives after original admission +10s, but less than five
    # seconds after DNS began. A newly granted ten-second budget accepts it.
    for packet, peer, end in pending.values():
        reply = packet[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + packet[12:end]
        reply += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('127.0.0.1')
        dns.sendto(reply, peer)
    for transport, origin in origins.items():
        receive(origin, second, f'{transport}: expired queued DNS packet leaked or blocked A2')
        senders[transport](None, origin.getsockname()[1], f'fresh-{transport}'.encode())
        receive(origin, f'fresh-{transport}'.encode(), f'{transport}: DNS cancellation killed the session')
    no_activity_until(time.monotonic() + .3, list(origins.values()), 'expired DNS result revived a packet')


def check_tunnels(stack, upstreams, start):
    peers = {}
    for kind, listener in upstreams.items():
        peer, _ = listener.accept()
        stack.enter_context(peer)
        peer.settimeout(2)
        hello = peer.recv(65535)
        if not hello or hello[0] != 22:
            raise RuntimeError(f'{kind}: outbound did not begin a TLS handshake')
        peers[peer] = kind
    closed = {}
    while peers:
        remaining = start + LATEST_CLOSE - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f'queued TLS dial obtained a fresh timeout: {list(peers.values())}')
        for peer in select.select(list(peers), [], [], remaining)[0]:
            if peer.recv(65535):
                continue
            elapsed = time.monotonic() - start
            kind = peers.pop(peer)
            if elapsed < 9:
                raise RuntimeError(f'{kind}: unrelated early dial failure at {elapsed:.2f}s')
            closed[kind] = round(elapsed, 3)
    print(f'TLS peer EOF times from original packet admission: {closed}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('fixture', help='quic-sniff supporting --fragments')
    parser.add_argument('--transport', action='append', choices=TRANSPORTS)
    parser.add_argument('--case', choices=('dns', 'tunnel', 'all'), default='all')
    args = parser.parse_args()
    kinds = tuple(dict.fromkeys(args.transport or TRANSPORTS))
    if 'uot' in kinds:
        version = subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout
        if 'Revision: 824dbcfb4dd0a95921840b1737b950cde590241e' not in version:
            raise RuntimeError('unexpected sing-box revision')
    first, second = fragments(args.fixture)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'tls-key'), '-out', str(root / 'cert'), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        secrets = {'password': 'secret', 'ss-key': base64.b64encode(bytes(range(16))).decode(),
                   'uuid': '00010203-0405-0607-0809-0a0b0c0d0e0f'}
        for name, value in secrets.items():
            (root / name).write_text(value)
            (root / name).chmod(0o600)
        (root / 'tls-key').chmod(0o600)
        (root / 'hello.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="example.com"\n')
        if args.case in ('dns', 'all'):
            run_case(args.binary, root, kinds, first, second, False)
        if args.case in ('tunnel', 'all'):
            run_case(args.binary, root, kinds, first, second, True)


if __name__ == '__main__':
    main()
