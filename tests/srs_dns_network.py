#!/usr/bin/env python3
"""SRS question predicates in DNS message and proxy resolution paths."""
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
from dns_rule_support import DnsPeer, Echo, exact, free_port, nexus_process, stream_request, wire_name

binary = pathlib.Path(sys.argv[1]).resolve()
revision = '824dbcfb4dd0a95921840b1737b950cde590241e'
assert f'Revision: {revision}' in subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout

def query(name, qtype, ident):
    return struct.pack('!HHHHHH', ident, 0x100, 1, 0, 0, 0) + wire_name(name) + struct.pack('!HH', qtype, 1)

def exchange(port, name, qtype, tcp):
    packet = query(name, qtype, 17)
    if tcp:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
            client.sendall(struct.pack('!H', len(packet)) + packet)
            response = exact(client, int.from_bytes(exact(client, 2), 'big'))
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.sendto(packet, ('127.0.0.1', port))
            response, _ = client.recvfrom(4096)
    assert response[:2] == b'\0\x11' and response[3] & 15 == 0, response.hex()

with tempfile.TemporaryDirectory(prefix='nexus-srs-dns-') as directory, DnsPeer() as first, DnsPeer() as second, Echo() as origin:
    root = pathlib.Path(directory)
    def compile_set(name, rules):
        source = root / f'{name}.json'
        source.write_text(json.dumps({'version': 2, 'rules': rules}))
        subprocess.run(['sing-box', 'rule-set', 'compile', str(source), '-o', str(root / f'{name}.srs')], check=True)
    compile_set('questions', [{'domain_suffix': ['split.test'], 'query_type': ['A']}])
    compile_set('source', [{'domain_suffix': ['source.test'], 'source_ip_cidr': ['192.0.2.0/24'], 'ip_cidr': ['127.0.0.0/8']}])
    compile_set('as-kdl', [{'domain_suffix': ['kdl.test'], 'query_type': ['A']}])
    compile_set('as-beve', [{'domain_suffix': ['beve.test'], 'query_type': ['AAAA']}])
    for fmt in ('kdl', 'beve'):
        subprocess.run([str(binary), 'rule', 'convert', 'srs', fmt, str(root / f'as-{fmt}.srs'), str(root / f'questions.{fmt}')], check=True)
    front, dns_port = free_port(), free_port()
    while front == dns_port:
        dns_port = free_port()
    config = root / 'config.kdl'
    config.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
dns {{ listen host="127.0.0.1" port={dns_port};
 server "first" type="udp" host="127.0.0.1" port={first.port};
 server "second" type="udp" host="127.0.0.1" port={second.port};
 rulesets {{
  questions path="questions.srs" format="srs"
  source path="source.srs" format="srs"
  questions-kdl path="questions.kdl" format="kdl"
  questions-beve path="questions.beve" format="beve"
 }}
 rule rule-set="questions" server="second";
 rule rule-set="questions-kdl" server="second";
 rule rule-set="questions-beve" server="second";
 rule rule-set="source" ip-cidr-match-source=#true server="second";
 final "first"; strategy "ipv4_only"; disable-cache #true;
}}
''')
    # A destination CIDR needs response semantics and must fail before listening.
    invalid = root / 'invalid.kdl'
    invalid.write_text(config.read_text().replace(' ip-cidr-match-source=#true', ''))
    rejected = subprocess.run([str(binary), 'run', '--config', str(invalid)], capture_output=True, text=True, timeout=5)
    if rejected.returncode == 0 or 'unsupported conditions' not in rejected.stderr:
        raise RuntimeError(f'destination CIDR was not rejected: {rejected.stderr}')
    with nexus_process(str(binary), str(config)):
        for tcp in (False, True):
            label = 'tcp' if tcp else 'udp'
            exchange(dns_port, f'{label}.split.test', 1, tcp)
            exchange(dns_port, f'{label}.split.test', 28, tcp)
            exchange(dns_port, f'{label}.source.test', 1, tcp)
            exchange(dns_port, f'{label}.other.test', 1, tcp)
            exchange(dns_port, f'{label}.kdl.test', 1, tcp)
            exchange(dns_port, f'{label}.beve.test', 28, tcp)
            if second.count(f'{label}.split.test', 1) != 1 or first.count(f'{label}.split.test', 28) != 1:
                raise RuntimeError('DNS query-type did not select the expected server')
            if second.count(f'{label}.source.test', 1) != 1 or first.count(f'{label}.other.test', 1) != 1:
                raise RuntimeError('DNS source CIDR or fallback did not select the expected server')
            if second.count(f'{label}.kdl.test', 1) != 1 or second.count(f'{label}.beve.test', 28) != 1:
                raise RuntimeError('converted KDL/BEVE question rules did not select the expected server')
        stream_request(front, origin.port, 'proxy.split.test')
        stream_request(front, origin.port, 'proxy.other.test')
        if second.count('proxy.split.test', 1) != 1 or first.count('proxy.other.test', 1) != 1:
            raise RuntimeError('internal DNS resolution ignored the SRS question rule')
print('SRS DNS question routing: UDP, TCP, source and proxy resolution passed')
