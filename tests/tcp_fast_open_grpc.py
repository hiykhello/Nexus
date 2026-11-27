#!/usr/bin/env python3
"""Exercise the production VLESS gRPC pool with TCP Fast Open."""
import pathlib
import os
import socket
import sys
import tempfile
import threading

from anytls_network import Origin
from anytls_proxy_network import CountedRelay, begin, payload, reply, targets_closed
from dns_rule_support import free_port, nexus_process
from grpc_network import REVISION, SERVICE, UUID, box
from grpc_tls_network import certificates, server_config
import subprocess

binary = pathlib.Path(sys.argv[1]).resolve()
version = subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout
if f'Revision: {REVISION}' not in version:
    raise RuntimeError('unexpected sing-box revision')
with tempfile.TemporaryDirectory(prefix='nexus-tfo-grpc-') as directory:
    root = pathlib.Path(directory)
    certificates(root)
    uuid = root / 'uuid'
    uuid.write_text(UUID + '\n')
    uuid.chmod(0o600)
    for workers in (1, 2):
        remote, front = free_port(), free_port()
        config = root / 'client.kdl'
        direct_fast = bool(os.getenv('NEXUS_TEST_TFO_DIRECT'))
        direct = 'outbound "direct" type="direct" { tcp-fast-open #true; }' if direct_fast else 'outbound "direct" type="direct"'
        dial = 'detour "direct";' if direct_fast else 'tcp-fast-open #true;'
        with box('sing-box', root, server_config(root, remote), remote), CountedRelay(remote) as relay, Origin(expected=2) as origin:
            config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
{direct}
outbound "edge" type="vless" {{
 server host="127.0.0.1" port={relay.port}
 authentication {{ uuid-file "{uuid}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
 {dial}
 transport "grpc" {{ service-name "{SERVICE}"; response-policy "sing-box-lite"; }}
}}
routing {{ final "edge"; }}
''')
            with nexus_process(binary, config):
                clients = []
                for _ in range(2):
                    client = begin(front, origin.port)
                    reply(client)
                    clients.append(client)
                errors = []
                def exchange(client):
                    try:
                        payload(client)
                        client.shutdown(socket.SHUT_WR)
                        while client.recv(4096):
                            pass
                    except Exception as error:
                        errors.append(repr(error))
                    finally:
                        client.close()
                threads = [threading.Thread(target=exchange, args=(client,)) for client in clients]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(15)
                if errors or any(thread.is_alive() for thread in threads):
                    raise RuntimeError(f'gRPC exchange failed: {errors}')
                targets_closed(origin, 2)
                if workers == 1 and relay.accepted != 1:
                    raise RuntimeError(f'expected pooled physical TLS connection, got {relay.accepted}')
            relay.wait(relay.accepted, relay.accepted)
        print(f'VLESS gRPC TFO concurrent streams and shutdown passed: workers={workers}', flush=True)
