"""QUIC Initial SNI routing across SOCKS and native SS UDP."""
import base64
import re
import socket
import struct
import sys
import tempfile
from pathlib import Path
from dns_rule_support import free_port, nexus_process, ss_client, udp_client


def main(binary):
    source = (Path(__file__).parent / 'quic_sniff.cpp').read_text()
    match = re.search(r'constexpr std::string_view sample_packet\s*=(.*?);', source, re.S)
    assert match
    initial = bytes.fromhex(''.join(re.findall(r'"([0-9a-f]+)"', match.group(1))))
    damaged = initial[:-1] + bytes([initial[-1] ^ 1])
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); port = free_port(); ss_port = free_port()
        while ss_port == port: ss_port = free_port()
        key = bytes(range(16)); (root / 'key').write_text(base64.b64encode(key).decode()); (root / 'key').chmod(0o600)
        (root / 'block.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="example.com"\n')
        (root / 'config.kdl').write_text(f'''schema-version 1
role "server"
inbounds {{
 socks5 "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
 shadowsocks "ss" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{root / 'key'}"; }}
}}
outbound "direct" type="direct"
routing {{ rule-set "block" path="block.kdl" format="kdl"; tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{ rule action="sniff"; rule action="reject" rule-set="block" domain-source="sniffed"; rule action="route" outbound="direct"; }}; default-outbound "direct"; }}
''')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin:
            origin.bind(('127.0.0.1', 0)); origin.settimeout(.4)
            header = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', origin.getsockname()[1])
            with nexus_process(binary, str(root / 'config.kdl'), listeners=2), udp_client(port) as socks, ss_client(root, ss_port, key) as ss:
                for client, relay in (socks, ss):
                    client.sendto(header + initial, relay)
                    try:
                        origin.recvfrom(4096)
                        raise RuntimeError('QUIC SNI reject forwarded the packet')
                    except TimeoutError: pass
                    client.sendto(header + damaged, relay)
                    origin.settimeout(3)
                    payload, source_addr = origin.recvfrom(4096)
                    if payload != damaged: raise RuntimeError('unknown packet was not preserved')
                    origin.sendto(payload, source_addr)
                    client.settimeout(3); reply, _ = client.recvfrom(4096)
                    if reply != header + damaged: raise RuntimeError('UDP reply mismatch')
                    origin.settimeout(.4)
    print('QUIC Initial sniff reject and unknown fallback through SOCKS and SS native passed')


if __name__ == '__main__': main(sys.argv[1])
