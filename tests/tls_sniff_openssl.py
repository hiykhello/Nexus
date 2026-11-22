#!/usr/bin/env python3
"""Feed real OpenSSL TLS 1.2/1.3 ClientHello records to the sniffer."""
import pathlib
import socket
import subprocess
import sys

fixture = pathlib.Path(sys.argv[1]).resolve()


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise RuntimeError('OpenSSL closed before ClientHello completed')
        data.extend(part)
    return bytes(data)


for version in ('-tls1_2', '-tls1_3'):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(5)
        client = subprocess.Popen(['openssl', 's_client', '-connect', f'127.0.0.1:{listener.getsockname()[1]}',
                                   '-servername', 'sniff.example', version],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with listener.accept()[0] as conn:
                conn.settimeout(5); records = bytearray(); handshake = bytearray(); size = None
                while size is None or len(handshake) < size + 4:
                    header = exact(conn, 5)
                    if header[0] != 22: raise RuntimeError(f'unexpected record {header!r}')
                    payload = exact(conn, int.from_bytes(header[3:], 'big'))
                    records.extend(header + payload); handshake.extend(payload)
                    if len(handshake) >= 4: size = int.from_bytes(handshake[1:4], 'big')
                result = subprocess.run([fixture, '--stdin'], input=records, stdout=subprocess.PIPE, check=True)
                if result.stdout != b'sniff.example\n': raise RuntimeError(f'{version}: {result.stdout!r}')
        finally:
            client.terminate(); client.wait(timeout=5)
print('OpenSSL TLS 1.2 and 1.3 ClientHello sniff passed')
