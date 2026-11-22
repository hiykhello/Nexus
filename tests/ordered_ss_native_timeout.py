"""Ordered SS native UDP honors a VLESS outbound's connection deadline."""
import base64
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from dns_rule_support import free_port, nexus_process, ss_client


def main(binary):
    key = bytes(range(16))
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'key').write_text(base64.b64encode(key).decode()); (root / 'key').chmod(0o600)
        (root / 'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f'); (root / 'uuid').chmod(0o600)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'tls-key'),
                        '-out', str(root / 'cert'), '-days', '1', '-subj', '/CN=cover.example',
                        '-addext', 'subjectAltName=DNS:cover.example'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        upstream = socket.socket(); upstream.bind(('127.0.0.1', 0)); upstream.listen(4); upstream.settimeout(5)
        front = free_port(); elapsed = []; errors = []
        (root / 'config.kdl').write_text(f'''schema-version 1
role "server"
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={front}; method "2022-blake3-aes-128-gcm"; key-file "{root / 'key'}"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ connect-timeout-ms 250; server host="127.0.0.1" port={upstream.getsockname()[1]}; authentication {{ uuid-file "{root / 'uuid'}"; }}; tls {{ server-name "cover.example"; ca-file "{root / 'cert'}"; verify #true; }} }}
routing {{ tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{ rule action="route" outbound="edge"; }}; default-outbound "edge"; }}
''')
        def hold():
            try:
                for _ in range(2):
                    connection, _ = upstream.accept()
                    with connection:
                        connection.settimeout(3); started = time.monotonic()
                        if not connection.recv(4096): raise RuntimeError('no TLS ClientHello')
                        while connection.recv(4096): pass
                        elapsed.append(time.monotonic() - started)
            except Exception as error: errors.append(error)
        thread = threading.Thread(target=hold); thread.start()
        try:
            with nexus_process(binary, str(root / 'config.kdl')), ss_client(root, front, key) as (client, relay):
                header = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', 9000)
                for i in range(2):
                    client.sendto(header + f'packet-{i}'.encode(), relay)
                    until = time.monotonic() + 3
                    while len(elapsed) <= i and not errors and time.monotonic() < until: time.sleep(.01)
                    if errors or len(elapsed) <= i: raise RuntimeError(f'no timeout completion: {elapsed!r}, {errors!r}')
                    if elapsed[-1] > 1.5: raise RuntimeError(f'connection deadline exceeded: {elapsed[-1]:.3f}s')
            print(f'ordered SS native UDP connection deadline and recovery passed: {elapsed!r}')
        finally:
            upstream.close(); thread.join(5)
            if thread.is_alive(): raise RuntimeError('upstream thread did not stop')


if __name__ == '__main__': main(sys.argv[1])
