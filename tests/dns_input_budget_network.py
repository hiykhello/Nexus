#!/usr/bin/env python3
"""Exercise shared raw DNS input reservations with real TCP and UDP sockets."""
import socket
import struct
import subprocess
import sys
import time
from dns_rule_support import exact, wire_name

binary = sys.argv[1]
question = struct.pack('!HHHHHH', 17, 0x100, 1, 0, 0, 0) + wire_name('budget.test') + b'\0\1\0\1'
for backend in ('epoll', 'uring'):
    process = subprocess.Popen([binary, backend], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = process.stdout.readline()
    if not line:
        error = process.stderr.read(); status = process.wait(timeout=3)
        if status == 77:
            print(f'{backend}: unavailable'); continue
        raise RuntimeError(f'{backend}: fixture failed ({status}): {error}')
    tcp, udp = map(int, line.split())
    blocker = socket.create_connection(('127.0.0.1', tcp), timeout=2)
    blocker.sendall(struct.pack('!H', 65535))
    time.sleep(.15)
    with socket.create_connection(('127.0.0.1', tcp), timeout=2) as denied:
        denied.settimeout(1); denied.sendall(struct.pack('!H', len(question)) + question)
        try: data = denied.recv(1)
        except ConnectionResetError: data = b''
        if data: raise RuntimeError(f'{backend}: TCP input budget did not reject')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1); client.sendto(question, ('127.0.0.1', udp))
        reply, _ = client.recvfrom(512)
        if reply[3] & 15 != 5: raise RuntimeError(f'{backend}: UDP listener failed while TCP budget full')
    blocker.close()
    deadline = time.monotonic() + 1
    while True:
        try:
            with socket.create_connection(('127.0.0.1', tcp), timeout=.5) as client:
                client.settimeout(.5); client.sendall(struct.pack('!H', len(question)) + question)
                reply = exact(client, int.from_bytes(exact(client, 2), 'big'))
                if reply[3] & 15 != 5: raise RuntimeError('incorrect recovered response')
                break
        except (OSError, RuntimeError):
            if time.monotonic() >= deadline: raise
            time.sleep(.02)
    # A maximum-length, valid EDNS request must still be accepted after the
    # prior reservation is returned.
    large = question[:10] + b'\0\1' + question[12:]
    option_size = 65535 - len(large) - 15
    large += b'\0\0\x29\x10\0\0\0\0\0' + struct.pack('!H', option_size + 4)
    large += struct.pack('!HH', 65001, option_size) + bytes(option_size)
    if len(large) != 65535: raise RuntimeError('bad maximum-length query fixture')
    with socket.create_connection(('127.0.0.1', tcp), timeout=1) as client:
        client.settimeout(1); client.sendall(struct.pack('!H', len(large)) + large)
        reply = exact(client, int.from_bytes(exact(client, 2), 'big'))
        if reply[3] & 15 != 5: raise RuntimeError(f'{backend}: maximum-length request failed')
    active = socket.create_connection(('127.0.0.1', tcp), timeout=1)
    active.sendall(struct.pack('!H', 65535))
    output, errors = process.communicate(timeout=7); active.close()
    if process.returncode or 'input budget drained and reused' not in output:
        raise RuntimeError(f'{backend}: exit={process.returncode} output={output!r} errors={errors!r}')
    print(f'{backend}: contention, rejection, recovery and active stop passed')
