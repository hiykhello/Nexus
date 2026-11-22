#!/usr/bin/env python3
"""Exercise a shared DNS generation across actual Server restarts."""
import argparse
from pathlib import Path
import subprocess
import threading

from detour_network import Dns
from dns_rule_support import Echo

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('fixture', type=Path)
args = parser.parse_args()
dns = Dns()
try:
    with Echo() as echo:
        process = subprocess.Popen([str(args.fixture.resolve(strict=True)), str(dns.port), str(echo.port)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        def release_after_initial():
            for line in process.stdout:
                print(line, end='', flush=True)
                if line.strip() == 'DNS initial stage complete':
                    if not {'first.test', 'second.test'}.issubset(dns.names):
                        process.kill(); return
                    dns.drops.update(('first.test', 'second.test'))
                    process.stdin.write('G'); process.stdin.flush()
        thread = threading.Thread(target=release_after_initial); thread.start()
        try:
            process.wait(timeout=35)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(); raise
        finally:
            thread.join(5)
        process.stdin.close(); process.stdout.close()
        diagnostics = process.stderr.read(); process.stderr.close()
        if process.returncode or thread.is_alive(): raise RuntimeError(f'fixture exit {process.returncode}: {diagnostics}')
        print('configured DNS received both names; cache served all requests after upstream was disabled')
finally:
    dns.close()
