#!/usr/bin/env python3
"""Run deadline and active cancellation against a routed packet blackhole."""
import subprocess
import sys

binary = sys.argv[1]
for command in (['ip','link','set','lo','up'], ['ip','addr','add','192.0.2.1/32','dev','lo'],
                ['iptables','-A','INPUT','-p','tcp','--dport','443','-j','DROP']):
    setup=subprocess.run(command,capture_output=True,text=True)
    if setup.returncode:raise RuntimeError(f'blackhole setup {command!r} failed: {setup.stderr}')
for backend in ('epoll','uring'):
    for mode in ('pre-canceled','expired','timeout','cancel'):
        result=subprocess.run([binary,backend,'443','blackhole',mode],capture_output=True,text=True,timeout=6)
        if result.returncode==77:
            print(f'{backend}: unavailable');break
        if result.returncode:
            raise RuntimeError(f'{backend}/{mode}: exit={result.returncode} out={result.stdout!r} err={result.stderr!r}')
        print(f'{backend}/{mode}: {result.stdout.strip() or "passed"}')
if len(sys.argv)>2:
    for backend in ('epoll','uring'):
      for mode in ('cancel','duplicate'):
        result=subprocess.run([sys.argv[2],backend,'443','blackhole',mode],capture_output=True,text=True,timeout=6)
        if result.returncode==77:continue
        if result.returncode:raise RuntimeError(f'{backend}/stream-{mode}: exit={result.returncode} out={result.stdout!r} err={result.stderr!r}')
        print(f'{backend}/stream-{mode}: {result.stdout.strip()}')
