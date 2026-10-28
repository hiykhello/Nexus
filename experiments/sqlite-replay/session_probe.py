#!/usr/bin/env python3
import subprocess
import select
import sys
import tempfile
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('usage: session_probe.py <nexus-sqlite-replay-experiment>')
with tempfile.TemporaryDirectory(prefix='nexus-session-sqlite-') as root:
    subprocess.run([sys.argv[1], str(Path(root) / 'state.db')], check=True, timeout=15)
    hold_path = str(Path(root) / 'held.db')
    contender_path = Path(root) / 'contender.db'
    owner = subprocess.Popen([sys.argv[1], hold_path, 'hold-owner'], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    try:
        if not select.select([owner.stdout], [], [], 10)[0] or owner.stdout.readline().strip() != 'ready':
            raise RuntimeError('owner did not acquire lock')
        contender = subprocess.run([sys.argv[1], str(contender_path)], timeout=15)
        if contender.returncode != 35 or contender_path.exists():
            raise AssertionError('contender was not rejected before opening database')
        owner.kill()
        owner.wait(timeout=5)
    finally:
        if owner.poll() is None:
            owner.kill()
            owner.wait()
    subprocess.run([sys.argv[1], hold_path, 'verify-before'], check=True, timeout=15)
    for stage in ('before', 'after', 'id-before', 'id-after'):
        path = str(Path(root) / f'crash-{stage}.db')
        proc = subprocess.Popen([sys.argv[1], path, f'crash-{stage}'], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([proc.stdout], [], [], 10)[0] or proc.stdout.readline().strip() != 'ready':
                raise RuntimeError(f'writer failed to reach {stage} crash point')
            proc.kill()
            proc.wait(timeout=5)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        subprocess.run([sys.argv[1], path, f'verify-{stage}'], check=True, timeout=15)
    path = str(Path(root) / 'ambiguous-id.db')
    subprocess.run([sys.argv[1], path, 'ambiguous-id'], check=True, timeout=15)
    subprocess.run([sys.argv[1], path, 'verify-id-after'], check=True, timeout=15)
    print('SQLite real session and ID reservation crash recovery passed')
