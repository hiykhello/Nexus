#!/usr/bin/env python3
"""A nonmatching response must not contaminate a later response generation."""
import pathlib
import socket
import subprocess
import sys

from dns_rule_support import DnsPeer

binary = pathlib.Path(sys.argv[1]).resolve()
for backend in ('epoll', 'uring'):
    with DnsPeer() as slow, DnsPeer() as fast:
        slow.delays['owner.test', 1] = .15
        reply = fast.reply

        def miss(packet, transport):
            response = reply(packet, transport)
            return response[:-4] + socket.inet_aton('203.0.113.8')

        fast.reply = miss
        result = subprocess.run([str(binary), str(slow.port), str(fast.port), backend, 'fallback'],
                                capture_output=True, timeout=8)
        if result.returncode == 77:
            print(f'{backend}: unavailable')
            continue
        if result.returncode or slow.count('owner.test', 1) != 1 or fast.count('owner.test', 1) != 1:
            raise RuntimeError(f'{backend}: exit={result.returncode}, stderr={result.stderr!r}, '
                               f'slow={slow.seen!r}, fast={fast.seen!r}')
        print(f'{backend}: first CIDR miss, later generation matched')
