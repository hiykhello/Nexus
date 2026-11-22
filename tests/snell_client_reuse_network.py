#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path
server, client = [Path(arg).resolve(strict=True) for arg in sys.argv[1:]]
for backend in ('0', '1'):
    p = subprocess.Popen([str(server)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        port = int(p.stdout.readline())
        subprocess.run([str(client), str(port), backend], check=True, timeout=12)
        _, errors = p.communicate(timeout=8)
        if p.returncode:
            raise RuntimeError(errors)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    print(f'Snell four sequential streams on one physical connection backend={backend} passed', flush=True)
