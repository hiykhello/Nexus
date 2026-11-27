#!/usr/bin/env python3
import subprocess
import sys
import tempfile
from pathlib import Path
from detour_network import reserve, running
binary = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory(prefix='snell-reuse-config-') as folder:
    root = Path(folder); psk = root/'psk'; psk.write_text('nexus-snell-test\n'); psk.chmod(0o600)
    for index, (field, accepted) in enumerate((('', True), ('reuse #true;', True), ('reuse #false;', True), ('reuse 1;', False),
                                                ('reuse #true; reuse #false;', False), ('reuse "true";', False), ('reuse;', False))):
        front, edge = reserve(), reserve(); config = root/f'{index}.kdl'
        config.write_text(f'''schema-version 1
role "client"
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="snell" {{ server host="127.0.0.1" port={edge}; version 4; psk-file "{psk}"; {field} }}
routing {{ final "edge"; }}
''')
        if accepted:
            with running([str(binary), 'run', '--config', str(config)], front, root/f'{index}.log'): pass
        else:
            result = subprocess.run([str(binary), 'run', '--config', str(config)], capture_output=True, text=True, timeout=8)
            if result.returncode == 0 or 'reuse' not in result.stderr: raise RuntimeError(f'configuration accepted: {field}: {result.stderr}')
print('Snell reuse config defaults, booleans and invalid fields passed')
