#!/usr/bin/env python3
"""Exercise the SS-2022 physical Fast Open path against sing-box."""
import base64
import pathlib
import socket
import subprocess
import sys
import tempfile

from anytls_network import Origin
from anytls_proxy_network import begin, payload, reply, targets_closed
from dns_rule_support import free_port, nexus_process
from grpc_network import REVISION, box

binary = pathlib.Path(sys.argv[1]).resolve()
version = subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout
if f'Revision: {REVISION}' not in version:
    raise RuntimeError('unexpected sing-box revision')
with tempfile.TemporaryDirectory(prefix='nexus-tfo-ss-') as directory:
    root = pathlib.Path(directory)
    key = base64.b64encode(bytes(range(16))).decode()
    keyfile = root / 'key'
    keyfile.write_text(key)
    keyfile.chmod(0o600)
    for workers in (1, 2):
        remote, front = free_port(), free_port()
        server = {'log': {'level': 'warn'}, 'inbounds': [{'type': 'shadowsocks', 'listen': '127.0.0.1',
                  'listen_port': remote, 'method': '2022-blake3-aes-128-gcm', 'password': key}],
                  'outbounds': [{'type': 'direct'}]}
        config = root / 'client.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={remote};
 method "2022-blake3-aes-128-gcm"; key-file "{keyfile}"; tcp-fast-open #true; }}
routing {{ final "edge"; }}
''')
        with box('sing-box', root, server, remote), Origin(expected=1) as origin:
            with nexus_process(binary, config):
                with begin(front, origin.port) as client:
                    reply(client)
                    payload(client)
                    client.shutdown(socket.SHUT_WR)
                    while client.recv(4096):
                        pass
                targets_closed(origin, 1)
        print(f'SS-2022 TFO TCP transfer and half-close passed: workers={workers}', flush=True)
