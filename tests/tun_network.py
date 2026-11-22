#!/usr/bin/env python3
"""Independent kernel readback and rollback tests in owned user/net namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError(f'{command}: {result.stdout} {result.stderr}')
    return result.stdout


def snapshot():
    links = []
    for item in json.loads(run(['ip', '-j', 'link', 'show'])):
        links.append({key: item[key] for key in ('ifindex', 'ifname', 'mtu', 'flags', 'ifalias', 'link_type') if key in item})
    addresses = []
    for item in json.loads(run(['ip', '-j', 'address', 'show'])):
        for address in item.get('addr_info', []):
            addresses.append({'device': item['ifname'], **{key: address[key] for key in
                ('family', 'local', 'prefixlen', 'scope', 'label', 'noprefixroute', 'nodad', 'secondary') if key in address}})
    routes = json.loads(run(['ip', '-j', '-4', 'route', 'show', 'table', 'all']))
    routes += json.loads(run(['ip', '-j', '-6', 'route', 'show', 'table', 'all']))
    for route in routes:
        for key in ('cache', 'expires', 'error', 'used', 'lastuse'): route.pop(key, None)
    ordered = lambda values: sorted(values, key=lambda value: json.dumps(value, sort_keys=True))
    return {'links': ordered(links), 'addresses': ordered(addresses), 'routes': ordered(routes)}


def setup(mode, effect):
    run(['ip', 'link', 'set', 'lo', 'up'])
    run(['ip', 'link', 'add', 'sentinel', 'type', 'dummy'])
    run(['ip', 'link', 'set', 'dev', 'sentinel', 'addrgenmode', 'none'])
    run(['ip', 'link', 'set', 'sentinel', 'up'])
    run(['ip', 'address', 'add', '10.99.0.1/24', 'dev', 'sentinel'])
    run(['ip', '-6', 'address', 'add', 'fd99::1/64', 'dev', 'sentinel', 'nodad'])
    run(['ip', 'route', 'add', '198.51.100.0/24', 'dev', 'sentinel', 'proto', 'static', 'metric', '1234'])
    run(['ip', '-6', 'route', 'add', 'fd99:2::/64', 'dev', 'sentinel', 'proto', 'static', 'metric', '1234'])
    if mode == 'conflict':
        if effect in ('address4', 'address6'):
            run(['ip', *(['-6'] if effect.endswith('6') else []), 'address', 'add',
                 'fd42::1/128' if effect.endswith('6') else '10.42.0.1/32', 'dev', 'sentinel',
                 *(['nodad'] if effect.endswith('6') else []), 'noprefixroute'])
        else:
            run(['ip', *(['-6'] if effect.endswith('6') else []), 'route', 'add',
                 'fd42::2/128' if effect.endswith('6') else '10.42.0.2/32', 'dev', 'sentinel',
                 'proto', 'static', 'metric', '1024'])


def read_line(process, timeout=10):
    if not select.select([process.stdout], [], [], timeout)[0]: raise RuntimeError('fixture readiness timed out')
    line = process.stdout.readline()
    if not line: raise RuntimeError(f'fixture stopped before readiness: {process.stderr.read()}')
    return json.loads(line)


def inspect_ready(report):
    links = json.loads(run(['ip', '-j', 'link', 'show', 'nx-lease']))
    if len(links) != 1 or links[0]['ifindex'] != report['ifindex'] or links[0]['mtu'] != 1420 or 'UP' not in links[0]['flags']:
        raise RuntimeError(f'kernel link MTU/identity/readiness mismatch: {links}')
    if not links[0].get('ifalias', '').startswith('nexus-') or len(links[0]['ifalias']) != 38:
        raise RuntimeError('kernel lease ownership marker missing')
    addresses = json.loads(run(['ip', '-j', 'address', 'show', 'dev', 'nx-lease']))[0]['addr_info']
    if {(item['family'], item['local'], item['prefixlen']) for item in addresses} != {('inet', '10.42.0.1', 24), ('inet6', 'fd42::1', 64)}:
        raise RuntimeError(f'kernel addresses or unexpected generated link-local: {addresses}')
    if any(not item.get('noprefixroute') for item in addresses) or not next(item for item in addresses if item['family'] == 'inet6').get('nodad'):
        raise RuntimeError(f'NOPREFIXROUTE/NODAD not installed: {addresses}')
    for family, destination, source, unused in (([], '10.42.0.2', '10.42.0.1', '10.42.0.99'), (['-6'], 'fd42::2', 'fd42::1', 'fd42::99')):
        routes = json.loads(run(['ip', '-j', *family, 'route', 'show', 'table', 'main', 'dev', 'nx-lease']))
        if len(routes) != 1 or routes[0]['dst'].split('/')[0] != destination or routes[0].get('metric') != 1024 or routes[0].get('prefsrc') != source:
            raise RuntimeError(f'kernel explicit split route mismatch: {routes}')
        selected = json.loads(run(['ip', '-j', *family, 'route', 'get', destination]))
        if len(selected) != 1 or selected[0].get('dev') != 'nx-lease': raise RuntimeError(f'kernel route selection failed: {selected}')
        denied = subprocess.run(['ip', *family, 'route', 'get', unused], capture_output=True)
        if denied.returncode == 0: raise RuntimeError('address configuration silently captured a whole prefix')


def inner(binary, original_net, original_user, mode, effect='', target=0):
    if os.stat('/proc/self/ns/net').st_ino == original_net or os.stat('/proc/self/ns/user').st_ino == original_user:
        raise RuntimeError('user/network namespaces were not independently isolated')
    setup(mode, effect); before = snapshot()
    command = [binary, str(original_net), str(original_user), mode, effect, str(target)]
    interactive = mode in ('interactive', 'foreign-alias', 'foreign-route', 'foreign-route6', 'foreign-device')
    started = time.monotonic()
    if interactive:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            report = read_line(process); inspect_ready(report)
            if mode == 'foreign-alias': run(['ip', 'link', 'set', 'dev', 'nx-lease', 'alias', 'foreign'])
            if mode in ('foreign-route', 'foreign-route6'):
                family = ['-6'] if mode.endswith('6') else []
                run(['ip', *family, 'route', 'replace', 'fd42::2/128' if family else '10.42.0.2/32',
                     'dev', 'sentinel', 'proto', 'static', 'metric', '1024', 'src', 'fd99::1' if family else '10.99.0.1'])
            if mode == 'foreign-device':
                run(['ip', 'link', 'delete', 'nx-lease'])
                run(['ip', 'link', 'add', 'nx-lease', 'type', 'dummy'])
                run(['ip', 'link', 'set', 'dev', 'nx-lease', 'mtu', '1600', 'alias', 'foreign'])
                replacement = json.loads(run(['ip', '-j', 'link', 'show', 'nx-lease']))[0]
                if replacement['ifindex'] == report['ifindex']: raise RuntimeError('fixture did not replace interface generation')
            process.stdin.write('stop\n'); process.stdin.flush()
            output, error = process.communicate(timeout=15)
            if process.returncode: raise RuntimeError(f'fixture failed {process.returncode}: {output} {error}')
            if mode == 'foreign-device':
                replacement = json.loads(run(['ip', '-j', 'link', 'show', 'nx-lease']))[0]
                if replacement['mtu'] != 1600 or replacement.get('ifalias') != 'foreign': raise RuntimeError('lease altered replacement device')
                run(['ip', 'link', 'delete', 'nx-lease'])
        finally:
            if process.poll() is None: process.kill(); process.communicate(timeout=3)
    else:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        output, error = result.stdout, result.stderr
        if result.returncode: raise RuntimeError(f'fixture failed {result.returncode}: {output} {error}')
    after = snapshot()
    if mode == 'persistent-after-claim':
        retained = [link for link in after['links'] if link['ifname'] == 'nx-lease']
        if len(retained) != 1: raise RuntimeError('fixture did not preserve the externally persistent TUN')
        run(['ip', 'tuntap', 'del', 'dev', 'nx-lease', 'mode', 'tun'])
        after = snapshot()
    if mode in ('foreign-route', 'foreign-route6'):
        destination = 'fd42::2' if mode.endswith('6') else '10.42.0.2'
        foreign = [route for route in after['routes'] if route.get('dev') == 'sentinel' and route.get('dst', '').split('/')[0] == destination]
        if len(foreign) != 1 or foreign[0].get('metric') != 1024: raise RuntimeError(f'third-party replacement route mismatch: foreign={foreign} routes={after["routes"]} stdout={output}')
        after['routes'].remove(foreign[0])
    if after != before: raise RuntimeError(f'kernel state not restored exactly: before={before} after={after} stdout={output}')
    print(json.dumps({'mode': mode, 'effect': effect, 'target': target, 'seconds': round(time.monotonic()-started, 3),
                      'kernel_sentinel_unchanged': True, 'stdout': output.strip()}), flush=True)


def main():
    if len(sys.argv) > 2 and sys.argv[2] == '--inner':
        inner(sys.argv[1], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6], int(sys.argv[7])); return
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('binary')
    parser.add_argument('--mode'); parser.add_argument('--effect', default=''); parser.add_argument('--target', type=int, default=0)
    parser.add_argument('--evidence',type=Path)
    parser.add_argument('--basic', action='store_true'); args = parser.parse_args()
    binary = str(Path(args.binary).resolve()); net = os.stat('/proc/self/ns/net').st_ino; user = os.stat('/proc/self/ns/user').st_ino
    # This negative test must reject before LinuxTun::create; it performs no host mutation.
    denied = subprocess.run([binary, str(net), str(user), 'plain'], capture_output=True, text=True, timeout=3)
    if denied.returncode != 1: raise RuntimeError('fixture accepted the external namespace')
    if args.mode: cases = [(args.mode, args.effect, args.target)]
    else:
        cases = [(mode, '', 0) for mode in ('interactive', 'ipv4-small', 'capacity', 'validation', 'persistent', 'moved', 'moved-active',
                                           'expired', 'kernel-reject', 'already-closed', 'namespace', 'foreign-alias', 'foreign-route', 'foreign-route6', 'foreign-device',
                                           'moved-back', 'moved-back-active', 'reused', 'abandoned', 'closed-before-start', 'persistent-after-claim',
                                           'shared-deadline', 'rollback-deadline', 'stop-deadline', 'destructor', 'destructor-active')]
        cases += [('conflict', kind, 0) for kind in ('exact4', 'exact6', 'specific4', 'specific6', 'address4', 'address6')]
        if not args.basic:
            cases += [('fault', kind, target) for kind in ('send', 'loss', 'overflow', 'truncated', 'sequence', 'sender', 'malformed') for target in range(1, 8)]
            cases += [('dump-fault', kind, target) for kind in ('send', 'loss', 'overflow', 'truncated', 'sequence', 'sender', 'malformed') for target in range(1, 7)]
            cases += [('cleanup-fault', 'send', target) for target in range(1, 3)]
            cases += [('cleanup-keepup', 'send', target) for target in (0, 2, 3, 4, 5)]
    evidence={'complete':False,'expected_count':len(cases),'case_count':0,'external_namespace_rejected':True,
              'binary':binary,'binary_sha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':[]}
    for mode, effect, target in cases:
        result=subprocess.run(['unshare', '-Urn', sys.executable, __file__, binary, '--inner', str(net), str(user), mode, effect, str(target)],
                              capture_output=True,text=True,timeout=30)
        print(result.stdout,end='',flush=True)
        if result.returncode: raise RuntimeError(f'case {(mode,effect,target)} failed: {result.stderr}')
        evidence['cases'].append(json.loads(result.stdout.strip()))
        evidence['case_count']=len(evidence['cases'])
        if args.evidence: args.evidence.write_text(json.dumps(evidence,indent=2)+'\n')
    evidence['complete']=evidence['case_count']==evidence['expected_count']
    if args.evidence: args.evidence.write_text(json.dumps(evidence,indent=2)+'\n')


if __name__ == '__main__': main()
