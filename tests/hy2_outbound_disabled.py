#!/usr/bin/env python3
"""A feature-disabled CLI rejects valid Hysteria 2 inbounds and outbounds."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='nexus-hy2-disabled-') as directory:
    root = Path(directory)
    config = root / 'nexus.kdl'
    config.write_text(f'''schema-version 1
role "client"
workers 1
inbound "local" type="socks5" {{ listen host="127.0.0.1" port=12345; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{ server host="127.0.0.1" port=443;
 authentication {{ password-file "{root / 'password'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
 quic {{ max-udp-payload-size 1200; disable-path-mtu-discovery #true; }}
}}
routing {{ final "edge"; }}
''')
    result = subprocess.run([str(args.binary.resolve(strict=True)), 'run', '--config', str(config)],
                            capture_output=True, text=True, timeout=5)
    if result.returncode == 0 or 'Hysteria2 outbound is not available in this build' not in result.stderr:
        raise RuntimeError(f'unexpected result {result.returncode}: {result.stdout} {result.stderr}')
    config.write_text(f'''schema-version 1
role "server"
workers 1
inbound "edge" type="hysteria2" {{ listen host="127.0.0.1" port=12345;
 authentication {{ user "test" password-file="{root / 'password'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
 quic {{ max-udp-payload-size 1500; disable-path-mtu-discovery #false; }}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
    result = subprocess.run([str(args.binary.resolve(strict=True)), 'run', '--config', str(config)],
                            capture_output=True, text=True, timeout=5)
    if result.returncode == 0 or 'Hysteria2 is unavailable in this build' not in result.stderr:
        raise RuntimeError(f'unexpected inbound result {result.returncode}: {result.stdout} {result.stderr}')
    print('Feature-disabled CLI explicitly rejects Hysteria 2 inbound and outbound')
