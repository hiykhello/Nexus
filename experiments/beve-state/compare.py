#!/usr/bin/env python3
"""Small synchronous store comparison, not a throughput benchmark."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

if len(sys.argv) != 4:
    raise SystemExit('usage: compare.py <beve-binary> <sqlite-binary> <temporary-parent>')
beve, sqlite, parent = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='nexus-state-compare-', dir=parent) as temp:
    root = Path(temp)
    beve_dir, sqlite_dir = root / 'beve', root / 'sqlite'
    beve_dir.mkdir(mode=0o700)
    sqlite_dir.mkdir(mode=0o700)
    for name, data in (('auth.key', b'B' * 32), ('instance.id', b'I' * 16), ('proxy.key', bytes(range(16)))):
        fd = os.open(beve_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
    subprocess.run([beve, str(beve_dir), 'bench'], check=True, timeout=120)
    subprocess.run([sqlite, str(sqlite_dir / 'state.db'), 'bench'], check=True, timeout=120)
