#!/usr/bin/env python3
"""Two real concurrent upstream queries; the pending one must cancel and drain."""
import pathlib
import subprocess
import sys
from dns_rule_support import DnsPeer

binary = pathlib.Path(sys.argv[1]).resolve()
for backend in ('epoll', 'uring'):
    with DnsPeer() as slow, DnsPeer() as fast:
        slow.drop.add(('owner.test', 1))
        result = subprocess.run([str(binary), str(slow.port), str(fast.port), backend], capture_output=True, timeout=8)
        if result.returncode == 77:
            print(f'{backend}: unavailable')
            continue
        if result.returncode or slow.count('owner.test', 1) != 1 or fast.count('owner.test', 1) != 1:
            raise RuntimeError(f'{backend}: exit={result.returncode}, stderr={result.stderr!r}, slow={slow.seen!r}, fast={fast.seen!r}')
        print(f'{backend}: fast query completed, slow query canceled and drained')
