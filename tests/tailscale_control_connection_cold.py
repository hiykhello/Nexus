#!/usr/bin/env python3
"""Cold new failures: fresh process per point, same-context recovery, natural exit."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
from tailscale_control_connection_network import Runner


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    parser.add_argument('--peer', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--max-position', type=int, default=10000)
    args = parser.parse_args()
    args.fixture = args.fixture.resolve(strict=True)
    args.peer = args.peer.resolve(strict=True)
    runner = Runner(SimpleNamespace(fixture=args.fixture, peer=args.peer,
        evidence=args.evidence, startup=None, lifecycle=None, layered=None, resources=None))
    evidence = {'complete': False, 'scope': 'cold direct new_delete allocator, fresh process per '
        'ordinary/array/aligned fault; failed launch/TLS/H2 typed register/Map/update must drain, '
        'recover using a new owner on the same context, zero shared budget, natural global-pool '
        'destruction with tracked-live=0; scheduling tail sampled, no all-schedules claim',
        'fixture_sha256': hashlib.sha256(args.fixture.read_bytes()).hexdigest(),
        'peer_sha256': hashlib.sha256(args.peer.read_bytes()).hexdigest(), 'backends': {}}
    def save():
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(evidence, indent=2)+'\n')
    def run(backend, index):
        with runner.peer(True) as (ready, peer):
            argv = [str(args.fixture), str(ready['port']), ready['control'], str(backend),
                    str(runner.root/'cert'), '1', str(index)]
            checked = subprocess.run(argv, capture_output=True, text=True, timeout=12)
            record = {'index': index, 'exit_code': checked.returncode, 'stdout': checked.stdout,
                'stderr': checked.stderr, 'argv': argv, 'peer_argv': peer}
            if 'natural-exit tracked-live=0 bytes=0' not in checked.stderr:
                raise RuntimeError(json.dumps(record, indent=2))
            if index==0:
                good = checked.returncode==0 and 'fired=false' in checked.stdout
            elif 'fired=true' in checked.stdout:
                good = checked.returncode==0 and 'fault-drained=true recovered=true' in checked.stdout
            else:
                good = checked.returncode==77 and 'fired=false' in checked.stdout
            if not good:
                raise RuntimeError(json.dumps(record, indent=2))
            return record
    for backend in (0, 1):
        entry = {'baseline': run(backend, 0), 'runs': [], 'first_success': None}
        evidence['backends'][str(backend)] = entry
        save()
        for index in range(1, args.max_position+1):
            record = run(backend, index)
            entry['runs'].append(record)
            save()
            if record['exit_code']==77:
                entry['first_success'] = index
                break
            if index%25==0:
                print(f'cold backend={backend} positions1..{index} drained/recovered/natural-live0', flush=True)
        else:
            raise RuntimeError('fault sweep exceeded explicit position bound')
        def maximum():
            records = [entry['baseline'], *entry['runs']]
            return max(int(re.search(r'audit calls=(\d+)', r['stdout'])[1])
                       for r in records if 'fired=false' in r['stdout'])
        start, end = max(1, min(entry['first_success'], maximum())-2), max(entry['first_success'], maximum())+6
        if end>args.max_position:
            raise RuntimeError('tail exceeds explicit position bound')
        for index in range(start, end+1):
            for _ in range(3):
                entry['runs'].append(run(backend, index))
                save()
        seen = {r['index'] for r in entry['runs'] if 'fired=true' in r['stdout']}
        while True:
            high = maximum()
            missing = [i for i in range(1, high+1) if i not in seen]
            if not missing:
                break
            for index in missing:
                for _ in range(32):
                    record = run(backend, index)
                    entry['runs'].append(record)
                    save()
                    if 'fired=true' in record['stdout']:
                        seen.add(index)
                        break
                else:
                    raise RuntimeError(f'position {index} remained non-firing; observed coverage incomplete')
        entry['actual_fired_through'] = maximum()
        entry['missing_actual_fired_positions'] = []
        save()
        print(f'cold backend={backend} actual fired1..{maximum()} complete', flush=True)
    evidence['complete'] = True
    save()


if __name__ == '__main__':
    main()
