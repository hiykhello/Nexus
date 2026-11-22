#!/usr/bin/env python3
"""Verify the configured QUIC side's actual outgoing UDP payload bound."""
import argparse
import re
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('log', type=Path); parser.add_argument('trace', type=Path)
parser.add_argument('--limit', type=int, required=True)
parser.add_argument('--side', choices=('client', 'server'), required=True)
args = parser.parse_args()
ports = re.findall(r'QUIC IPv[46] server port (\d+)', args.log.read_text())
if len(ports) != 1: raise RuntimeError(f'expected one server port, got {ports!r}')
port = int(ports[0]); sizes = {'client': [], 'server': []}
pattern = re.compile(r'sendmsg\(\d+, \{msg_name=\{sa_family=AF_INET6?, sin6?_port=htons\((\d+)\).*?iov_len=(\d+)\}.*MSG_NOSIGNAL\).* = (\d+)$')
for line in args.trace.read_text().splitlines():
    match = pattern.search(line)
    if not match: continue
    dest, count, sent = map(int, match.groups())
    if count != sent: raise RuntimeError('short UDP send')
    sizes['client' if dest == port else 'server'].append(count)
other = 'server' if args.side == 'client' else 'client'
if not sizes[args.side] or not sizes[other]: raise RuntimeError(f'missing direction: {sizes!r}')
if max(sizes[args.side]) > args.limit: raise RuntimeError(f'{args.side} exceeded limit: {max(sizes[args.side])}')
if max(sizes[other]) <= args.limit: raise RuntimeError(f'{other} did not demonstrate larger packets: {max(sizes[other])}')
print(f'{args.side} max={max(sizes[args.side])}, {other} max={max(sizes[other])}; packets={len(sizes[args.side])}/{len(sizes[other])}')
