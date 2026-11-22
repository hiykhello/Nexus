#!/usr/bin/env python3
"""Probe Linux datagram ICMP identifier rewriting in a private net namespace."""
import os
import socket
import struct
import subprocess
import sys


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data)//2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def probe(family, protocol, destination):
    sockets = [socket.socket(family, socket.SOCK_DGRAM, protocol) for _ in range(2)]
    try:
        assigned = []
        for sock in sockets:
            sock.settimeout(3)
            sock.connect((destination, 0))
            identifier = sock.getsockname()[1]
            if not identifier:
                raise RuntimeError('kernel did not assign an identifier')
            assigned.append(identifier)
        if len(set(assigned)) != len(assigned):
            raise RuntimeError(f'ping socket identifiers collide: {assigned}')
        for index, sock in enumerate(sockets):
            for sequence in (10, 11):
                body = bytes((index, sequence)) + b'odd'
                request = struct.pack('!BBHHH', 8 if family == socket.AF_INET else 128,
                                      0, 0, 0x1234, sequence) + body
                if sock.send(request) != len(request):
                    raise RuntimeError('short ping socket send')
        for index, sock in enumerate(sockets):
            seen = set()
            for _ in range(2):
                reply = sock.recv(65535)
                if len(reply) < 8:
                    raise RuntimeError('truncated echo reply')
                kind, code, _, identifier, sequence = struct.unpack('!BBHHH', reply[:8])
                if (kind, code, identifier) != (0 if family == socket.AF_INET else 129, 0, assigned[index]):
                    raise RuntimeError(f'unexpected reply header: {reply.hex()}')
                if sequence not in (10, 11) or reply[8:] != bytes((index, sequence)) + b'odd':
                    raise RuntimeError(f'unexpected reply payload: {reply.hex()}')
                pseudo = b''
                if family == socket.AF_INET6:
                    address = socket.inet_pton(family, destination)
                    pseudo = address + address + struct.pack('!I3xB', len(reply), protocol)
                if checksum(pseudo + reply):
                    raise RuntimeError(f'invalid echo checksum: {reply.hex()}')
                seen.add(sequence)
            if seen != {10, 11}:
                raise RuntimeError(f'duplicate or missing replies: {seen}')
        print(f'IPv{4 if family == socket.AF_INET else 6}: '
              f'two sockets assigned distinct IDs; sequences and payloads preserved')
    finally:
        for sock in sockets:
            sock.close()


if len(sys.argv) == 1:
    parent = str(os.stat('/proc/self/ns/net').st_ino)
    subprocess.run(['unshare', '-Urn', sys.executable, __file__, parent], check=True, timeout=15)
else:
    if os.stat('/proc/self/ns/net').st_ino == int(sys.argv[1]):
        raise RuntimeError('network namespace is not isolated')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    # The private namespace maps only the calling user's group to group 0.
    subprocess.run(['sysctl', '-qw', 'net.ipv4.ping_group_range=0 0'], check=True)
    probe(socket.AF_INET, socket.IPPROTO_ICMP, '127.0.0.1')
    probe(socket.AF_INET6, socket.IPPROTO_ICMPV6, '::1')
