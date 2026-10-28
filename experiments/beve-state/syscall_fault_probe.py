#!/usr/bin/env python3
"""Inject EIO at snapshot syscalls exercised by the actual UDP callbacks."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != 'aes256'):
    raise SystemExit('usage: syscall_fault_probe.py <fixture> [aes256]')
binary = str(Path(sys.argv[1]).resolve())
source = Path(__file__).with_name('fault_inject.c')

with tempfile.TemporaryDirectory(prefix='nexus-beve-syscall-') as root:
    root = Path(root)
    library = root / 'fault.so'
    subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(library)], check=True)
    for kind in ('session', 'id'):
        for stage in ('write', 'file-sync', 'rename', 'dir-sync'):
            directory = root / f'{kind}-{stage}'
            directory.mkdir(mode=0o700)
            for name, value in (('auth.key', b'B' * 32), ('instance.id', b'I' * 16),
                                ('proxy.key', bytes(range(32 if len(sys.argv) == 3 else 16)))):
                fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    output.write(value)
            subprocess.run([binary, str(directory), f'{kind}-init'], check=True, timeout=10)
            env = os.environ.copy()
            env.update(LD_PRELOAD=str(library), NEXUS_FAULT_STAGE=stage,
                       # ID path commits receive, then wall, then ID reservation.
                       NEXUS_FAULT_SAVE='1' if kind == 'session' else '3')
            result = subprocess.run([binary, str(directory), f'{kind}-fail-syscall'],
                                    env=env, capture_output=True, timeout=10, check=True)
            if result.stderr.count(b'nexus injected EIO\n') != 1:
                raise AssertionError(f'{kind}/{stage}: fault was not hit exactly once: {result.stderr!r}')
            expected = 'new' if stage == 'dir-sync' else 'old'
            subprocess.run([binary, str(directory), f'{kind}-verify-{expected}'], check=True, timeout=10)
print('syscall fault probes passed')
