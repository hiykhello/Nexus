#!/usr/bin/env python3
"""Exercise serial response quota on the production TCP and SS UDP paths."""
import pathlib
import subprocess
import sys
from dns_rule_support import DnsPeer

for binary in sys.argv[1:]:
    binary = pathlib.Path(binary).resolve()
    for backend in ('epoll', 'uring'):
      for scenario in ('serial-budget', 'serial-cancel', 'race-result-budget'):
        with DnsPeer() as upstream, DnsPeer() as fallback:
            if scenario == 'serial-cancel':
                fallback.drop.add(('alias.test', 1))
            result = subprocess.run([str(binary), str(upstream.port), str(fallback.port), backend, scenario],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 77:
                print(f'{binary.name}/{backend}: unavailable')
                continue
            expected = upstream.count('alias.test', 1) >= 1 and (fallback.count('alias.test', 1) == 1 if scenario == 'serial-cancel' else not fallback.seen)
            if result.returncode or not expected:
                raise RuntimeError(f'{binary.name}/{backend}: exit={result.returncode}, '
                                   f'out={result.stdout!r}, err={result.stderr!r}, '
                                   f'upstream={upstream.seen!r}, fallback={fallback.seen!r}')
            print(f'{binary.name}/{backend}/{scenario}: passed')
