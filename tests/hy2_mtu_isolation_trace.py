#!/usr/bin/env python3
"""Check a strace of hy2_mtu_isolation for the shared-socket MTU boundary."""
import re
import sys

trace = open(sys.argv[1], encoding='utf-8')
pattern = re.compile(r'^(\d+) (\S+) sendmsg\((\d+), .*sin_port=htons\((\d+)\).*inet_addr\("(127\.0\.0\.[23])"\).*iov_len=(\d+)\}.*= (.*)$')
rejected = None
small = healthy = False
for line in trace:
    match = pattern.match(line)
    if not match: continue
    pid, timestamp, fd, port, address, length, result = match.groups()
    length = int(length)
    if rejected is None and address == '127.0.0.2' and length > 1208 and result.startswith('-1 EMSGSIZE'):
        rejected = (pid, fd, port, timestamp, length)
    if rejected is None or (pid, fd) != rejected[:2] or timestamp <= rejected[3]: continue
    if address == '127.0.0.2' and port == rejected[2] and length <= 1240 and result == str(length): small = True
    if address == '127.0.0.3' and port != rejected[2] and length > 1240 and result == str(length): healthy = True
if not rejected or not small or not healthy:
    raise SystemExit(f'missing shared-socket evidence: rejected={rejected!r}, smaller={small}, healthy={healthy}')
print(f'server thread={rejected[0]} fd={rejected[1]} rejected={rejected[4]} bytes; same socket sent smaller affected and large unaffected packets')
