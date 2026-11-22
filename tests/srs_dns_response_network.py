#!/usr/bin/env python3
"""SRS destination CIDR evaluated against actual DNS responses and HTTPS hints."""
import base64
import ipaddress
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
from dns_rule_support import DnsPeer, Echo, datagram_request, exact, free_port, nexus_process, question, ss_client, stream_request, wire_name

binary = pathlib.Path(sys.argv[1]).resolve()
revision = '824dbcfb4dd0a95921840b1737b950cde590241e'
assert f'Revision: {revision}' in subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout

def exchange(port, name, qtype, tcp, rcode=0):
    packet = struct.pack('!HHHHHH', 23, 0x100, 1, 0, 0, 0) + wire_name(name) + struct.pack('!HH', qtype, 1)
    if tcp:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
            client.sendall(struct.pack('!H', len(packet)) + packet)
            response = exact(client, int.from_bytes(exact(client, 2), 'big'))
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.sendto(packet, ('127.0.0.1', port))
            response, _ = client.recvfrom(4096)
    if response[:2] != b'\0\x17' or response[3] & 15 != rcode:
        raise RuntimeError(f'{name}: unexpected DNS response {response.hex()}')

with tempfile.TemporaryDirectory(prefix='nexus-srs-response-') as directory, DnsPeer() as first, DnsPeer() as fallback, Echo() as origin:
    root = pathlib.Path(directory)
    source = root / 'rules.json'
    source.write_text(json.dumps({'version': 2, 'rules': [{'domain_suffix': ['domain-match.test'],
        'ip_cidr': ['127.0.0.0/8', '192.0.2.0/24', '::1/128', '2001:db8::/32']}]}))
    subprocess.run(['sing-box', 'rule-set', 'compile', str(source), '-o', str(root / 'rules.srs')], check=True)
    original_reply = first.reply
    def reply(packet, transport):
        name, kind, end = question(packet)
        if kind != 65:
            result = original_reply(packet, transport)
            if result and kind == 1 and ('wrong' in name or 'domain-match' in name):
                result = result[:-4] + socket.inet_aton('203.0.113.8')
            return result
        first.seen.append((name, kind, transport))
        v4 = socket.inet_aton('203.0.113.1' if 'misshint' in name or 'hint6' in name else '192.0.2.5')
        v6 = ipaddress.IPv6Address('2001:db9::1' if 'misshint' in name or 'hint4' in name else '2001:db8::1').packed
        params = struct.pack('!HH', 4, len(v4)) + v4 + struct.pack('!HH', 6, len(v6)) + v6
        if 'badhint' in name:
            params = struct.pack('!HH', 4, 3) + b'\xc0\x00\x02'
        data = b'\0\1\0' + params
        rr = b'\xc0\x0c' + struct.pack('!HHIH', 65, 1, 60, len(data)) + data
        return packet[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + packet[12:end] + rr
    first.reply = reply
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
routing {{ default-outbound "direct"; }}
dns {{ listen host="127.0.0.1" port={dns_port};
 server "first" type="udp" host="127.0.0.1" port={first.port};
 server "fallback" type="udp" host="127.0.0.1" port={fallback.port};
 rule-set "response" path="rules.srs" format="srs";
 rule action="evaluate" server="first";
 rule rule-set="response" match-response=#true action="respond";
 rule action="route" server="fallback";
 strategy "ipv4_only"; disable-cache #true;
}}
''')
    with nexus_process(str(binary), str(config), 2), ss_client(root, ss_port, key) as ss_udp:
        for tcp in (False, True):
            label = 'tcp' if tcp else 'udp'
            first.no_data.add((f'{label}.nodata.test', 1))
            for name, qtype, expected in ((f'{label}.match.test', 1, False), (f'{label}.v6.test', 28, False), (f'{label}.wrong.test', 1, True),
                    (f'{label}.domain-match.test', 1, False), (f'{label}.hint.test', 65, False),
                    (f'{label}.hint4.test', 65, False), (f'{label}.hint6.test', 65, False),
                    (f'{label}.misshint.test', 65, True), (f'{label}.nodata.test', 1, True)):
                exchange(dns_port, name, qtype, tcp)
                if first.count(name, qtype) != 1 or fallback.count(name, qtype) != int(expected):
                    raise RuntimeError(f'{name}: wrong response decision: {first.seen!r}, {fallback.seen!r}')
            exchange(dns_port, f'{label}.badhint.test', 65, tcp, rcode=2)
            if fallback.count(f'{label}.badhint.test', 65):
                raise RuntimeError('malformed HTTPS hints silently reached fallback')
        exchange(dns_port, 'nx.test', 1, False, rcode=3)
        if first.count('nx.test', 1) != 1 or fallback.count('nx.test', 1) != 1:
            raise RuntimeError('NXDOMAIN was incorrectly treated as an address match')
        stream_request(front, origin.port, 'proxy.match.test')
        stream_request(front, origin.port, 'proxy.wrong.test')
        if first.count('proxy.match.test', 1) != 1 or fallback.count('proxy.match.test', 1) or \
           first.count('proxy.wrong.test', 1) != 1 or fallback.count('proxy.wrong.test', 1) != 1:
            raise RuntimeError('proxy internal response rule selected the wrong upstream')
        client, relay = ss_udp
        datagram_request(client, relay, origin.port, 'ss.match.test')
        datagram_request(client, relay, origin.port, 'ss.wrong.test')
        if first.count('ss.match.test', 1) != 1 or fallback.count('ss.match.test', 1) or \
           first.count('ss.wrong.test', 1) != 1 or fallback.count('ss.wrong.test', 1) != 1:
            raise RuntimeError('SS UDP internal response rule selected the wrong upstream')
print('SRS DNS response routing: A, HTTPS hints, domain OR, malformed data and proxy resolution passed')
