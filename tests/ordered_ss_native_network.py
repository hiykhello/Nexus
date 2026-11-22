"""Ordered SS-2022 native UDP through direct and UoT outbounds."""
import base64
import json
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from dns_rule_support import DnsPeer, Echo, datagram_request, free_port, nexus_process, ss_client


def main(binary):
    revision = '824dbcfb4dd0a95921840b1737b950cde590241e'
    if f'Revision: {revision}' not in subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError('unexpected sing-box revision')
    with tempfile.TemporaryDirectory() as directory, Echo() as echo, DnsPeer() as dns:
        root = Path(directory)
        key = bytes(range(16))
        password = base64.b64encode(key).decode()
        (root / 'key').write_text(password)
        (root / 'key').chmod(0o600)
        upstream = free_port()
        (root / 'box.json').write_text(json.dumps({
            'log': {'level': 'error'},
            'inbounds': [{'type': 'shadowsocks', 'listen': '127.0.0.1', 'listen_port': upstream,
                          'method': '2022-blake3-aes-128-gcm', 'password': password}],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}))
        box = subprocess.Popen(['sing-box', 'run', '-c', root / 'box.json'], stderr=subprocess.PIPE)
        try:
            time.sleep(.2)
            if box.poll() is not None:
                raise RuntimeError(f'upstream failed: {box.stderr.read()!r}')
            for outbound in ('direct', 'tunnel'):
                front = free_port()
                tunnel = (f'outbound "tunnel" type="shadowsocks" {{ server host="127.0.0.1" port={upstream}; '
                          f'method "2022-blake3-aes-128-gcm"; key-file "{root / "key"}"; udp-over-tcp "v2"; }}') if outbound == 'tunnel' else ''
                (root / 'rule.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="blocked.example"\n')
                (root / 'config.kdl').write_text(f'''schema-version 1
role "server"
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={front}; method "2022-blake3-aes-128-gcm"; key-file "{root / 'key'}"; }}
outbound "direct" type="direct"
{tunnel}
dns {{ servers {{ udp "resolver" host="127.0.0.1" port={dns.port}; }}; final "resolver"; strategy "ipv4_only"; disable-cache #true; }}
routing {{ rule-set "blocked" path="rule.kdl" format="kdl"; tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{ rule action="sniff"; rule action="reject" rule-set="blocked" domain-source="sniffed"; rule action="resolve"; rule action="route" outbound="{outbound}"; }}; default-outbound "{outbound}"; }}
''')
                with nexus_process(binary, str(root / 'config.kdl')), ss_client(root, front, key) as (client, relay):
                    header = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', echo.port)
                    for payload in (b'first-' + outbound.encode(), b'second-' + outbound.encode()):
                        client.sendto(header + payload, relay)
                        response, _ = client.recvfrom(65535)
                        if response != header + payload:
                            raise RuntimeError(f'{outbound}: incorrect reply {response!r}')
                    before = dns.count('native.test', 1)
                    datagram_request(client, relay, echo.port, 'native.test')
                    if dns.count('native.test', 1) == before:
                        raise RuntimeError(f'{outbound}: target was not resolved by configured DNS')
                    query = bytes.fromhex('123401000001000000000000') + b'\x07blocked\x07example\x00\x00\x01\x00\x01'
                    client.sendto(header + query, relay)
                    client.settimeout(.4)
                    try:
                        response, _ = client.recvfrom(65535)
                        raise RuntimeError(f'{outbound}: rejected query received {response!r}')
                    except TimeoutError:
                        pass
            print('ordered SS native UDP direct, UoT, DNS resolution, sniff rejection and shutdown passed')
        finally:
            box.terminate()
            _, errors = box.communicate(timeout=5)
            if box.returncode:
                raise RuntimeError(f'upstream exit {box.returncode}: {errors!r}')


if __name__ == '__main__':
    main(sys.argv[1])
