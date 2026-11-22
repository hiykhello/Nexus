#!/usr/bin/env python3
"""A feature-disabled CLI rejects a valid MASQUE inbound before opening UDP."""
import pathlib
import socket
import subprocess
import sys
import tempfile

binary, cert, key = (pathlib.Path(value).resolve(strict=True) for value in sys.argv[1:4])
with tempfile.TemporaryDirectory(prefix='nexus-masque-disabled-') as directory:
    root = pathlib.Path(directory)
    token = root/'token'; token.write_text('approved'); token.chmod(0o600)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
    config = root/'config.kdl'
    config.write_text(f'''schema-version 1
role "server"
workers 1
inbound "masque" type="masque" {{
 listen host="127.0.0.1" port={port}
 authority "localhost"
 authentication {{ bearer-file "{token}"; }}
 tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
 allow cidr="127.0.0.0/8" first-port=1 last-port=65535
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    result = subprocess.run([binary, 'run', '--config', config], capture_output=True, text=True, timeout=10)
    if result.returncode == 0 or 'MASQUE is unavailable in this build' not in result.stderr:
        raise RuntimeError(f'disabled MASQUE was not rejected: {result.returncode} {result.stderr}')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as check:
        check.bind(('127.0.0.1', port))
print('Feature-disabled MASQUE rejected before binding UDP')
