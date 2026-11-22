#!/usr/bin/env python3
"""Hold an actual UDP lookup while TCP and UDP compete for parsed-query bytes."""
import socket
import struct
import subprocess
import sys
import threading
import time
from dns_rule_support import exact, wire_name


def packet(name, size, ident):
    q = struct.pack('!HHHHHH', ident, 0x100, 1, 0, 0, 1) + wire_name(name) + b'\0\1\0\1'
    return q + b'\0\0\x29\x10\0\0\0\0\0' + struct.pack('!H', size+4) + struct.pack('!HH', 65001, size) + bytes(size)

for backend in ('epoll', 'uring'):
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(('127.0.0.1', 0)); upstream.settimeout(5)
    proc = subprocess.Popen([sys.argv[1], backend, str(upstream.getsockname()[1])], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line=proc.stdout.readline()
    if not line:
        errors=proc.stderr.read(); code=proc.wait(timeout=2); upstream.close()
        if code==77: print(f'{backend}: unavailable'); continue
        raise RuntimeError(f'{backend}: fixture exit {code}: {errors}')
    tcp, udp = map(int,line.split())
    first=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);first.settimeout(3)
    first.sendto(packet('hold.test',15000,1),('127.0.0.1',udp))
    request, peer=upstream.recvfrom(65535)
    # While the first lookup is active its retained query exceeds 15 KiB.
    with socket.create_connection(('127.0.0.1',tcp),timeout=1) as denied:
        denied.settimeout(1); body=packet('denied.test',8000,2);denied.sendall(struct.pack('!H',len(body))+body)
        try: value=denied.recv(1)
        except ConnectionResetError: value=b''
        if value: raise RuntimeError(f'{backend}: TCP accepted despite query budget')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as denied:
        denied.settimeout(.2);denied.sendto(packet('denied.test',8000,3),('127.0.0.1',udp))
        try: denied.recvfrom(100);raise RuntimeError(f'{backend}: UDP accepted despite query budget')
        except socket.timeout: pass
    # Complete the held query, then reuse the allowance without another
    # packet reaching its owning listener first.
    end=12
    while request[end]: end+=request[end]+1
    end+=5
    answer=request[:2]+struct.pack('!HHHHH',0x8180,1,0,0,0)+request[12:end]
    upstream.sendto(answer,peer);first.recvfrom(512);first.close()
    with socket.create_connection(('127.0.0.1',tcp),timeout=1) as client:
        client.settimeout(2);body=packet('recover.test',8000,4);client.sendall(struct.pack('!H',len(body))+body)
        request,peer=upstream.recvfrom(65535)
        end=12
        while request[end]: end+=request[end]+1
        end+=5
        upstream.sendto(request[:2]+struct.pack('!HHHHH',0x8180,1,0,0,0)+request[12:end],peer)
        reply=exact(client,int.from_bytes(exact(client,2),'big'))
        if reply[:2]!=b'\0\4':raise RuntimeError(f'{backend}: recovery failed')
    # Stop while another query still holds the reservation.
    active=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    active.sendto(packet('stop.test',15000,5),('127.0.0.1',udp));upstream.recvfrom(65535)
    output,errors=proc.communicate(timeout=7);active.close();upstream.close()
    if proc.returncode or 'listener query reservations drained' not in output:
        raise RuntimeError(f'{backend}: exit={proc.returncode} output={output!r} error={errors!r}')
    print(f'{backend}: UDP/TCP parsed-query competition, release, recovery and active stop passed')
