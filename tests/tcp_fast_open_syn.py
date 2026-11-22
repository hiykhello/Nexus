#!/usr/bin/env python3
"""Observe first and cookie-bearing Fast Open SYNs in an isolated netns.

Run with: unshare -Urn python3 tests/tcp_fast_open_syn.py <fixture>
"""
import socket
import struct
import subprocess
import sys
import threading

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
        tcp_start = 14 + ip_header
        if len(packet) < tcp_start + 20:
            continue
        _, destination = struct.unpack_from('!HH', packet, tcp_start)
        flags = packet[tcp_start + 13]
        if destination != port or not flags & 2 or flags & 16:
            continue
        total = struct.unpack_from('!H', packet, 16)[0]
        tcp_header = (packet[tcp_start + 12] >> 4) * 4
        records.append((total - ip_header - tcp_header, packet[tcp_start + 20:tcp_start + tcp_header].hex()))


def serve():
    try:
        for _ in range(2):
            with listener.accept()[0] as peer:
                peer.settimeout(5)
                received = 0
                while received < 200000:
                    data = peer.recv(65536)
                    if not data:
                        raise RuntimeError('short payload')
                    received += len(data)
                peer.sendall(b'\x5a')
    except Exception as error:
        errors.append(repr(error))


capture_thread = threading.Thread(target=capture)
server_thread = threading.Thread(target=serve)
capture_thread.start()
server_thread.start()
for _ in range(2):
    result = subprocess.run([sys.argv[1], 'epoll', str(port), 'v4', 'send'],
                            capture_output=True, text=True, timeout=6)
    if result.returncode:
        errors.append((result.returncode, result.stdout, result.stderr))
server_thread.join(6)
stopped.set()
capture_thread.join(2)
listener.close()
raw.close()
print('SYN payload lengths and options:', records)
if server_thread.is_alive() or capture_thread.is_alive() or errors:
    raise RuntimeError(f'capture or peer failed: {errors}')
if not any(length > 0 for length, _ in records):
    raise RuntimeError('no SYN carrying data was observed')
