#!/usr/bin/env python3
"""Test a numeric server receive rate with a controlled HTTP/3 peer."""
import argparse
from pathlib import Path
import subprocess
import tempfile

from detour_network import exact, reserve, socks
from dns_rule_support import nexus_process
from hy2_outbound_detour import udp_port
from udp_bind_port_network import certificate

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
parser.add_argument('peer', type=Path)
args = parser.parse_args()
binary, peer = args.binary.resolve(strict=True), args.peer.resolve(strict=True)
with tempfile.TemporaryDirectory(prefix='hy2-peer-rate-') as directory:
    root = Path(directory)
    certificate(root)
    password = root / 'password'
    password.write_text('test-password\n'); password.chmod(0o600)
    for family, host in ((4, '127.0.0.1'), (6, '::1')):
        port, front = udp_port(host), reserve()
        config = root / 'client.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers 1
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{ server host="{host}" port={port};
 authentication {{ password-file "{password}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
routing {{ default-outbound "edge"; }}
''')
        server = subprocess.Popen([str(peer), str(family), str(port), str(root / 'cert'), str(root / 'key')],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if server.stdout.readline().strip() != 'READY': raise RuntimeError('controlled peer failed to start')
            with nexus_process(str(binary), str(config)):
                with socks(front, 1, ('127.0.0.1', 12345))[0] as client:
                    client.settimeout(8)
                    payload = bytes(range(256)) * 512
                    client.sendall(payload); client.shutdown(1)
                    if exact(client, len(payload)) != payload or client.recv(1): raise RuntimeError('TCP echo or FIN mismatch')
            out, err = server.communicate(timeout=6)
            if server.returncode or 'numeric receive rate and TCP echo verified' not in out:
                raise RuntimeError(f'controlled peer failed: {server.returncode} {out} {err}')
            print(f'IPv{family}: numeric peer receive rate accepted; TCP and FIN passed', flush=True)
        finally:
            if server.poll() is None:
                server.kill(); server.communicate()
