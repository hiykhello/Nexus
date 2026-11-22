#!/usr/bin/env python3
"""Exercise non-installable Map projection over actual TLS/Noise/H2."""
import argparse
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    parser.add_argument('peer', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    fixture, peer = args.fixture.resolve(strict=True), args.peer.resolve(strict=True)
    records = []
    with tempfile.TemporaryDirectory(prefix='nexus-ts-map-policy-') as temporary:
        root = Path(temporary)
        cert, key = root / 'cert', root / 'key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        for backend in (0, 1):
            for mode in ('basic', 'application', 'tka', 'policy'):
                env = os.environ.copy()
                if mode in ('tka', 'policy'): env['NEXUS_TEST_SECURITY'] = mode
                else: env.pop('NEXUS_TEST_SECURITY', None)
                command = [str(peer), '--cert', str(cert), '--key', str(key)]
                if backend: command.extend(['--early', '--coalesce'])
                proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
                try:
                    if not select.select([proc.stdout], [], [], 8)[0]: raise RuntimeError('peer readiness timed out')
                    ready = json.loads(proc.stdout.readline())
                    fixture_command = [str(fixture), str(ready['port']), ready['control'], str(backend), str(cert), str(backend)]
                    if mode != 'basic': fixture_command.append('application' if mode == 'application' else 'security-' + mode)
                    run = subprocess.run(fixture_command, capture_output=True, text=True, timeout=15)
                    record = {'backend': backend, 'early': bool(backend), 'coalesce': bool(backend), 'mode': mode,
                              'exit': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
                    records.append(record)
                    args.report.write_text(json.dumps(records, indent=2) + '\n')
                    print(record, flush=True)
                    if run.returncode or 'control-connection-passed' not in run.stdout:
                        raise RuntimeError('fixture did not complete')
                    if mode in ('tka', 'policy') and ('rejected=true' not in run.stdout or 'ready-before-failure=true' not in run.stdout):
                        raise RuntimeError('projection was not observed before rejection and revocation')
                finally:
                    proc.terminate()
                    try: proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.communicate()


if __name__ == '__main__':
    main()
