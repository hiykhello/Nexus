#!/usr/bin/env python3
"""Observe production message-race launch failure with a real UDP upstream."""
import socket
import subprocess
import sys

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
    upstream.bind(('127.0.0.1', 0))
    for backend in ('epoll', 'uring'):
        run = subprocess.run([sys.argv[1], backend, str(upstream.getsockname()[1])],
                             capture_output=True, text=True, timeout=8)
        if run.returncode == 77:
            print(f'{backend}: unavailable')
            continue
        if run.returncode:
            raise RuntimeError(f'{backend}: exit={run.returncode} output={run.stdout!r} error={run.stderr!r}')
        print(f'{backend}: {run.stdout.strip()}')
