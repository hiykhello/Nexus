#!/usr/bin/env python3
"""DNS concurrency fields must be rejected by the response-disabled build."""
import pathlib
import subprocess
import sys
import tempfile
from dns_rule_support import free_port

binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='nexus-race-disabled-') as directory:
    config = pathlib.Path(directory) / 'config.kdl'
    for field in ('race=#false', 'speculative=#false', 'race=#true', 'speculative=#true'):
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={free_port()}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
dns {{ server "a" type="udp" host="127.0.0.1"; rule action="route" server="a" {field}; }}
''')
        result = subprocess.run([str(binary), 'run', '--config', str(config)], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 or 'unavailable in this build' not in result.stderr or 'listening' in result.stdout:
            raise RuntimeError(f'{field}: disabled feature was not rejected: {result.stderr!r}')
print('DNS race/speculative rejected in response-disabled build')
