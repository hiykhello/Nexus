#!/usr/bin/env python3
"""Named evaluate results retain their own response and upstream context."""
import base64
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
from dns_rule_support import DnsPeer, Echo, datagram_request, exact, free_port, nexus_process, question, ss_client, stream_request, wire_name

binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='nexus-dns-named-') as directory, DnsPeer() as first, DnsPeer() as second, Echo() as origin:
    root = pathlib.Path(directory)
    old_reply = first.reply
    def first_reply(packet, transport):
        response = old_reply(packet, transport)
        if response and question(packet)[0].startswith('first.'):
            return response[:-4] + socket.inet_aton('192.0.2.5')
        return response
    first.reply = first_reply
    old_second_reply = second.reply
    def second_reply(packet, transport):
        name, kind, end = question(packet)
        if name not in ('alias.match.test', 'ssalias.match.test') or kind != 1:
            return old_second_reply(packet, transport)
        second.seen.append((name, kind, transport))
        cname = wire_name('target.test')
        rr = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 60, len(cname)) + cname
        return packet[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + packet[12:end] + rr
    second.reply = second_reply
    front, dns_port, ss_port = free_port(), free_port(), free_port()
    while dns_port == front:
        dns_port = free_port()
    while ss_port in (front, dns_port):
        ss_port = free_port()
    key = bytes(range(16));key_path = root / 'key'
    key_path.write_text(base64.b64encode(key).decode());key_path.chmod(0o600)
    config = root / 'config.kdl'
    config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
 shadowsocks "ss" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{key_path}"; }} }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
dns {{ listen host="127.0.0.1" port={dns_port};
 server "first" type="udp" host="127.0.0.1" port={first.port};
 server "second" type="udp" host="127.0.0.1" port={second.port};
 rulesets {{ "loopback" path="loopback.kdl" format="kdl"; }}
 rule action="evaluate" server="first" tag="first-result" rewrite-ttl=4;
 rule action="evaluate" server="second" tag="second-result" rewrite-ttl=7;
 rule domain-suffix="rule.test" rule-set="loopback" match-response="second-result" action="respond";
 rule domain-suffix="match.test" match-response="second-result" action="respond";
 rule domain="first.test" match-response="first-result" action="respond";
 rule action="evaluate" server="second";
 rule action="respond" match-response=#true;
 strategy "ipv4_only"; disable-cache #true;
}}
''')
    (root / 'loopback.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.0/8"\n')
    invalid = root / 'invalid.kdl'
    for content in (config.read_text().replace('tag="second-result"', 'tag="first-result"'),
                    config.read_text().replace('match-response="second-result"', 'match-response="missing"'),
                    config.read_text().replace('action="evaluate" server="first" tag="first-result"', 'action="route" server="first" tag="first-result"')):
        invalid.write_text(content)
        run = subprocess.run([str(binary), 'run', '--config', str(invalid)], capture_output=True, text=True, timeout=5)
        if run.returncode == 0:
            raise RuntimeError('invalid named response configuration accepted')
    def ask(name, tcp, expected, ttl):
        packet = struct.pack('!HHHHHH', 17, 0x100, 1, 0, 0, 0) + wire_name(name) + b'\0\1\0\1'
        if tcp:
            with socket.create_connection(('127.0.0.1', dns_port), timeout=3) as client:
                client.sendall(struct.pack('!H', len(packet)) + packet)
                response = exact(client, int.from_bytes(exact(client, 2), 'big'))
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3);client.sendto(packet, ('127.0.0.1', dns_port));response, _ = client.recvfrom(4096)
        if response[3] & 15 or response[-4:] != socket.inet_aton(expected) or struct.unpack_from('!I', response, len(packet)+6)[0] != ttl:
            raise RuntimeError(f'{name}: wrong tagged response {response.hex()}')
    with nexus_process(str(binary), str(config), 2), ss_client(root, ss_port, key) as ss_udp:
        for tcp in (False, True):
            ask('first.test', tcp, '192.0.2.5', 4)
            ask('second.match.test', tcp, '127.0.0.1', 7)
            ask('second.rule.test', tcp, '127.0.0.1', 7)
            ask('anonymous.test', tcp, '127.0.0.1', 60)
        stream_request(front, origin.port, 'proxy.match.test')
        stream_request(front, origin.port, 'alias.match.test')
        client, relay = ss_udp
        datagram_request(client, relay, origin.port, 'ss.match.test')
        datagram_request(client, relay, origin.port, 'ssalias.match.test')
        for name in ('proxy.match.test', 'ss.match.test'):
            if first.count(name, 1) != 1 or second.count(name, 1) != 1:
                raise RuntimeError(f'{name}: named response or anonymous fallback was not used')
        if second.count('target.test', 1) != 2 or first.count('target.test', 1):
            raise RuntimeError('CNAME continuation did not use the selected named upstream')
print('named DNS responses: UDP/TCP, rule-set selection, TTL, anonymous and TCP/SS UDP resolution passed')
