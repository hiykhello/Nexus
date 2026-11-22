#!/usr/bin/env python3
"""Two independent response lookups run concurrently; cancel only one."""
import pathlib
import subprocess
import sys
from dns_rule_support import DnsPeer

binary = pathlib.Path(sys.argv[1]).resolve()
for backend in ('epoll', 'uring'):
    for mode in ('independent', 'coalesce'):
        with DnsPeer() as slow, DnsPeer() as fast:
            if mode == 'independent':
                slow.drop.add(('slow.test', 1))
                fast.delays['fast.test', 1] = .3
            else:
                slow.delays['shared.test', 1] = .3
            command = [str(binary), str(slow.port), str(fast.port), backend]
            if mode == 'coalesce':
                command.append(mode)
            result = subprocess.run(command, capture_output=True, timeout=8)
            if result.returncode == 77:
                print(f'{backend}: unavailable')
                break
            expected = (slow.count('slow.test', 1) == 1 and fast.count('fast.test', 1) == 1) if mode == 'independent' else \
                slow.count('shared.test', 1) == 1 and not fast.seen
            if result.returncode or not expected:
                raise RuntimeError(f'{backend}/{mode}: exit={result.returncode}, stderr={result.stderr!r}, slow={slow.seen!r}, fast={fast.seen!r}')
            print(f'{backend}/{mode}: cancellation preserves the other response and drains')
