#!/usr/bin/env python3
"""Verify direct first-write deadlines against an isolated TCP blackhole."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

from dns_rule_support import connect, free_port, nexus_process

for command in (['ip', 'link', 'set', 'lo', 'up'], ['ip', 'addr', 'add', '192.0.2.1/32', 'dev', 'lo'],
                ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '443', '-j', 'DROP']):
    subprocess.run(command, check=True, capture_output=True)
with tempfile.TemporaryDirectory(prefix='nexus-direct-tfo-blackhole-') as directory:
    root = pathlib.Path(directory)
    front = free_port()
    config = root / 'client.kdl'
    config.write_text(f'''schema-version 1
role "client"
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{ tcp-fast-open #true; connect-timeout-ms 300; }}
routing {{ final "direct"; }}
''')
    with nexus_process(pathlib.Path(sys.argv[1]).resolve(), config):
        for request in (b'GET http://192.0.2.1:443/test HTTP/1.1\r\nHost: 192.0.2.1:443\r\n\r\n',
                        b'CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\n\r\nfirst bytes'):
            with connect(front) as client:
                client.settimeout(3)
                started = time.monotonic()
                client.sendall(request)
                response = client.recv(4096)
                elapsed = time.monotonic() - started
                if not response.startswith(b'HTTP/1.1 502') or not 0.2 < elapsed < 2:
                    raise RuntimeError(f'blackhole failure: elapsed={elapsed:.3f}, response={response!r}')
print('direct HTTP forward and CONNECT blackhole honored original 300ms deadline')
