#!/usr/bin/env python3
"""Reject invalid production Hysteria 2 datagram detour configurations."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
binary = parser.parse_args().binary.resolve(strict=True)


def hy2(name, extra=''):
    return f'''outbound "{name}" type="hysteria2" {{ server host="127.0.0.1" port=443;
 authentication {{ password-file "/tmp/password"; }}
 tls {{ server-name "localhost"; ca-file "/tmp/cert"; verify #true; }}; {extra} }}'''


cases = [
    ('SS without UoT', hy2('edge', 'detour "lower";') + '''
outbound "lower" type="shadowsocks" { server host="127.0.0.1" port=8388; method "2022-blake3-aes-128-gcm"; key-file "/tmp/key"; }''', 'UDP-over-TCP'),
    ('lower Hy2 UDP disabled', hy2('edge', 'detour "lower";') + '\n' + hy2('lower', 'quic { udp #false; }'), 'requires UDP'),
    ('cycle', hy2('edge', 'detour "lower";') + '\n' + hy2('lower', 'detour "edge";'), 'cycle'),
    ('layered socket option', hy2('edge', 'detour "lower"; udp-bind-port 1234;') + '\n' + hy2('lower'), 'socket settings'),
    ('missing lower', hy2('edge', 'detour "missing";'), 'detour'),
]
with tempfile.TemporaryDirectory(prefix='nexus-hy2-detour-config-') as directory:
    path = Path(directory) / 'config.kdl'
    for name, outbounds, expected in cases:
        path.write_text('''schema-version 1
role "client"
inbound "local" type="socks5" { listen host="127.0.0.1" port=12345; authentication "none"; }
outbound "direct" type="direct"
''' + outbounds + '\nrouting { final "edge"; }\n')
        result = subprocess.run([str(binary), 'run', '--config', str(path)], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 or expected.lower() not in result.stderr.lower():
            raise RuntimeError(f'{name}: unexpected result {result.returncode}: {result.stdout} {result.stderr}')
        print(f'{name}: rejected', flush=True)
