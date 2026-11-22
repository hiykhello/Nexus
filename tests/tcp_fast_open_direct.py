#!/usr/bin/env python3
"""Exercise direct HTTP forwarding and observe Fast Open SYN data in a netns.

Run with: unshare -Urn python3 tests/tcp_fast_open_direct.py <nexus>
"""
import pathlib
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading

from dns_rule_support import connect, exact, free_port, nexus_process

subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
with open('/proc/sys/net/ipv4/tcp_fastopen', 'w') as control:
    control.write('3')
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
raw.bind(('lo', 0))
raw.settimeout(0.1)
listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 8)
listener.listen(8)
listener.settimeout(5)
port = listener.getsockname()[1]
records = []
errors = []
stopped = threading.Event()


def capture():
    while not stopped.is_set():
        try:
            packet = raw.recv(65535)
        except TimeoutError:
            continue
        if len(packet) < 54 or packet[12:14] != b'\x08\x00' or packet[23] != 6:
            continue
        ip_header = (packet[14] & 15) * 4
        start = 14 + ip_header
        if len(packet) < start + 20:
            continue
        _, destination = struct.unpack_from('!HH', packet, start)
        flags = packet[start + 13]
        if destination != port or not flags & 2 or flags & 16:
            continue
        total = struct.unpack_from('!H', packet, 16)[0]
        tcp_header = (packet[start + 12] >> 4) * 4
        records.append(total - ip_header - tcp_header)


def serve():
    try:
        for _ in range(2):
            with listener.accept()[0] as peer:
                peer.settimeout(5)
                request = bytearray()
                while not request.endswith(b'\r\n\r\n'):
                    data = peer.recv(8192)
                    if not data or len(request) + len(data) > 8192:
                        raise RuntimeError('incomplete or duplicated request')
                    request += data
                if not request.startswith(b'GET /test HTTP/1.1\r\n') or request.count(b'GET ') != 1:
                    raise RuntimeError(f'incorrect rewritten request: {request!r}')
                peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
    except Exception as error:
        errors.append(repr(error))


capture_thread = threading.Thread(target=capture)
server_thread = threading.Thread(target=serve)
capture_thread.start()
server_thread.start()
try:
    with tempfile.TemporaryDirectory(prefix='nexus-direct-tfo-') as directory:
        root = pathlib.Path(directory)
        front = free_port()
        config = root / 'client.kdl'
        ordered = 'tcp-program sniff-timeout-ms=100 unknown="skip" { rule action="sniff"; rule action="route" outbound="direct"; };' if os.getenv('NEXUS_TEST_ORDERED') else ''
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{ tcp-fast-open #true; }}
routing {{ {ordered} default-outbound "direct"; }}
''')
        with nexus_process(pathlib.Path(sys.argv[1]).resolve(), config):
            for _ in range(2):
                with connect(front) as client:
                    client.settimeout(5)
                    client.sendall(f'GET http://127.0.0.1:{port}/test HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n'.encode())
                    response = bytearray()
                    while data := client.recv(8192):
                        response.extend(data)
                    if not response.startswith(b'HTTP/1.1 200') or not response.endswith(b'\r\n\r\nOK'):
                        raise RuntimeError(f'incorrect response: {response!r}')
    server_thread.join(5)
finally:
    stopped.set()
    capture_thread.join(2)
    listener.close()
    raw.close()
if server_thread.is_alive() or capture_thread.is_alive() or errors:
    raise RuntimeError(f'direct peer failed: {errors}')
if not any(length > 0 for length in records):
    raise RuntimeError(f'no request data observed in SYN: {records}')
print(f'direct HTTP rewrite sent exactly once; SYN payload lengths={records}')
