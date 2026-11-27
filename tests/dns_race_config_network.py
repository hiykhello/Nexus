#!/usr/bin/env python3
"""Configured race is exercised by DNS UDP/TCP, proxy TCP and SS UDP."""
import base64
import concurrent.futures
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time
from dns_rule_support import DnsPeer, Echo, connect, datagram_request, exact, free_port, nexus_process, question, ss_client, stream_request, wire_name

binary = pathlib.Path(sys.argv[1]).resolve()
stop_mode = sys.argv[2] if len(sys.argv) > 2 else 'all'
with tempfile.TemporaryDirectory(prefix='nexus-race-config-') as directory, DnsPeer() as slow, DnsPeer() as fast, Echo() as origin:
    root = pathlib.Path(directory)
    original = slow.reply
    def pending(packet, transport):
        name, kind, _ = question(packet)
        if name.endswith('.race.test') or name == 'race.test':
            slow.seen.append((name, kind, transport)); return None
        return original(packet, transport)
    slow.reply = pending
    front, dns_port, ss_port = free_port(), free_port(), free_port()
    while dns_port == front: dns_port = free_port()
    while ss_port in (front, dns_port): ss_port = free_port()
    key = bytes(range(16)); key_file = root / 'key'
    key_file.write_text(base64.b64encode(key).decode()); key_file.chmod(0o600)
    config = root / 'config.kdl'
    text = f'''schema-version 1
role "server"
workers 2
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
 shadowsocks "ss" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{key_file}"; }} }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
dns {{ listen host="127.0.0.1" port={dns_port};
 server "slow" type="udp" host="127.0.0.1" port={slow.port};
 server "fast" type="udp" host="127.0.0.1" port={fast.port};
 rule action="evaluate" server="slow" tag="slow";
 rule match-response="slow" race=#true action="respond";
 rule action="evaluate" server="fast" tag="fast" speculative=#true;
 rule match-response="fast" race=#true action="respond";
 strategy "ipv4_only"; disable-cache #true;
}}
'''
    config.write_text(text)
    invalid = root / 'invalid.kdl'
    variants = [text.replace('match-response="slow" race=#true', 'race=#true'),
                text.replace('race=#true action="respond"', 'race=#true speculative=#true action="respond"', 1),
                text.replace('speculative=#true;', 'speculative="yes";'),
                text.replace('race=#true action="respond"', 'race=#true action="evaluate" server="slow"', 1)]
    variants.append(text.replace(' rule action="evaluate" server="slow" tag="slow";',
        ' rule action="evaluate" server="slow";\n' * 33 + ' rule action="evaluate" server="slow" tag="slow";'))
    variants.append(text.replace(' rule match-response="slow" race=#true action="respond";',
        ' rule match-response="slow" race=#true action="respond";\n' * 65))
    for variant in variants:
        invalid.write_text(variant)
        result = subprocess.run([str(binary), 'run', '--config', str(invalid)], capture_output=True, timeout=5)
        if result.returncode == 0: raise RuntimeError('invalid race configuration accepted')
    def ask(name, tcp):
        packet = struct.pack('!HHHHHH', 17, 0x100, 1, 0, 0, 0) + wire_name(name) + b'\0\1\0\1'
        if tcp:
            with socket.create_connection(('127.0.0.1', dns_port), timeout=3) as client:
                client.sendall(struct.pack('!H', len(packet)) + packet)
                response = exact(client, int.from_bytes(exact(client, 2), 'big'))
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3); client.sendto(packet, ('127.0.0.1', dns_port)); response, _ = client.recvfrom(4096)
        if response[3] & 15 or response[-4:] != socket.inet_aton('127.0.0.1'):
            raise RuntimeError(f'{name}: invalid response {response.hex()}')
    with nexus_process(str(binary), str(config), 2), ss_client(root, ss_port, key) as ss_udp:
        for tcp in (False, True): ask(('tcp' if tcp else 'udp') + '.race.test', tcp)
        stream_request(front, origin.port, 'proxy.race.test')
        datagram_request(*ss_udp, origin.port, 'ss.race.test')
        for name in ('udp.race.test', 'tcp.race.test', 'proxy.race.test', 'ss.race.test'):
            if slow.count(name, 1) != 1 or fast.count(name, 1) != 1:
                raise RuntimeError(f'{name}: missing concurrent upstream queries: slow={slow.seen!r}, fast={fast.seen!r}')
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda n: ask(f'parallel{n}.race.test', n % 2 == 0), range(8)))
        ask('after.race.test', False)
    names = ('stop-dns.race.test', 'stop-proxy.race.test', 'stop-ss.race.test')
    fast.drop.update((name, 1) for name in names)
    with nexus_process(str(binary), str(config), 2) as process, ss_client(root, ss_port, key) as ss_udp, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_client, connect(front) as proxy_client:
        if stop_mode in ('all', 'dns'):
            dns_client.sendto(struct.pack('!HHHHHH', 18, 0x100, 1, 0, 0, 0) + wire_name(names[0]) + b'\0\1\0\1', ('127.0.0.1', dns_port))
        if stop_mode in ('all', 'proxy'):
            proxy_client.sendall(b'\x05\x01\0')
            if exact(proxy_client, 2) != b'\x05\0': raise RuntimeError('SOCKS handshake failed')
            raw = names[1].encode(); proxy_client.sendall(b'\x05\x01\0\x03' + bytes([len(raw)]) + raw + struct.pack('!H', origin.port))
        if stop_mode in ('all', 'ss'):
            raw = names[2].encode(); ss_udp[0].sendto(b'\0\0\0\x03' + bytes([len(raw)]) + raw + struct.pack('!H', origin.port) + b'pending', ss_udp[1])
        selected = names if stop_mode == 'all' else (names[{'dns': 0, 'proxy': 1, 'ss': 2}[stop_mode]],)
        deadline = time.monotonic() + 4
        while any(not slow.count(name, 1) or not fast.count(name, 1) for name in selected):
            if time.monotonic() >= deadline: raise RuntimeError('not all pending race queries started')
            time.sleep(.01)
        started = time.monotonic(); process.terminate(); process.wait(timeout=3)
        if time.monotonic() - started > 2: raise RuntimeError('active races did not drain on stop')
print('configured DNS race: UDP/TCP, proxy, SS UDP, invalid rules and concurrent recovery passed')
