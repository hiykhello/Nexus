"""SS-2022 native UDP routed through a VLESS XUDP outbound."""
import base64
import concurrent.futures
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
        key = bytes(range(16)); password = base64.b64encode(key).decode()
        (root / 'ss-key').write_text(password); (root / 'ss-key').chmod(0o600)
        uuid = '00010203-0405-0607-0809-0a0b0c0d0e0f'
        (root / 'uuid').write_text(uuid); (root / 'uuid').chmod(0o600)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'tls-key'),
                        '-out', str(root / 'cert'), '-days', '1', '-subj', '/CN=cover.example',
                        '-addext', 'subjectAltName=DNS:cover.example'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root / 'tls-key').chmod(0o600)
        upstream, front = free_port(), free_port()
        (root / 'box.json').write_text(json.dumps({
            'log': {'level': 'debug'},
            'inbounds': [{'type': 'vless', 'listen': '127.0.0.1', 'listen_port': upstream,
                          'users': [{'uuid': uuid}], 'tls': {'enabled': True, 'certificate_path': str(root / 'cert'),
                                                             'key_path': str(root / 'tls-key')}}],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}))
        box = subprocess.Popen(['sing-box', 'run', '-c', root / 'box.json'], stderr=subprocess.PIPE)
        try:
            time.sleep(.2)
            if box.poll() is not None: raise RuntimeError(f'upstream failed: {box.stderr.read()!r}')
            (root / 'config.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={front}; method "2022-blake3-aes-128-gcm"; key-file "{root / 'ss-key'}"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={upstream}; authentication {{ uuid-file "{root / 'uuid'}"; }}; tls {{ server-name "cover.example"; ca-file "{root / 'cert'}"; verify #true; }} }}
dns {{ servers {{ udp "resolver" host="127.0.0.1" port={dns.port}; }}; final "resolver"; strategy "ipv4_only"; disable-cache #true; }}
routing {{ tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{ rule action="resolve"; rule action="route" outbound="edge"; }}; default-outbound "edge"; }}
''')
            with nexus_process(binary, str(root / 'config.kdl')):
                # Each client uses a distinct sing-box config path.
                def exchange(index):
                    path = root / str(index); path.mkdir()
                    with ss_client(path, front, key) as (client, relay):
                        for host, family, tag in [('127.0.0.1', socket.AF_INET, b'\x01'), ('::1', socket.AF_INET6, b'\x04')]:
                            header = b'\x00\x00\x00' + tag + socket.inet_pton(family, host) + struct.pack('!H', echo.port)
                            for number in range(2):
                                payload = f'{index}-{host}-{number}'.encode()
                                client.sendto(header + payload, relay)
                                try:
                                    response, _ = client.recvfrom(65535)
                                except TimeoutError as error:
                                    raise RuntimeError(f'XUDP timeout for {index}, {host}, {number}; received={echo.received!r}') from error
                                if response != header + payload: raise RuntimeError(f'XUDP response mismatch: {response!r}')
                        datagram_request(client, relay, echo.port, 'xudp.test')
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                    for future in [pool.submit(exchange, i) for i in range(3)]: future.result(timeout=25)
                if dns.count('xudp.test', 1) == 0: raise RuntimeError('no explicit target DNS lookup')
            print('ordered SS native UDP XUDP dual stack, DNS, concurrent sessions and shutdown passed')
        finally:
            box.terminate(); _, errors = box.communicate(timeout=5)
            if sys.exc_info()[0] is not None: print(errors.decode(errors='replace'), file=sys.stderr)
            if box.returncode: raise RuntimeError(f'upstream exit {box.returncode}: {errors!r}')


if __name__ == '__main__':
    main(sys.argv[1])
