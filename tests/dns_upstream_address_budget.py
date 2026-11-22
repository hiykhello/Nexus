#!/usr/bin/env python3
import socket
import subprocess
import sys

with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as slow, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as fast:
    slow.bind(('127.0.0.1',0));fast.bind(('127.0.0.1',0))
    for binary in sys.argv[1:]:
        for backend in ('epoll','uring'):
            result=subprocess.run([binary,str(slow.getsockname()[1]),str(fast.getsockname()[1]),backend,'budget'],capture_output=True,text=True,timeout=8)
            if result.returncode==77:print(f'{binary}/{backend}: unavailable');continue
            if result.returncode:raise RuntimeError(f'{binary}/{backend}: exit={result.returncode}, out={result.stdout!r}, err={result.stderr!r}')
            print(f'{binary}/{backend}: receive exhaustion propagated and drained')
