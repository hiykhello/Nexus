#!/usr/bin/env python3
"""One lightweight idle-capacity sample per unused-outbound configuration."""
import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tests'))
from dns_rule_support import free_port, nexus_process, udp_client


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def proc_sample(pid):
    proc = Path('/proc') / str(pid)
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    memory = {}
    for line in (proc / 'smaps_rollup').read_text().splitlines():
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        if key in ('Rss', 'Anonymous', 'Pss', 'Private_Clean', 'Private_Dirty'):
            memory[key + '_kib'] = int(value.split()[0])
    # Fields following comm start at field 3; utime/stime are 14/15.
    return {'monotonic_ns': time.monotonic_ns(), 'unix_ns': time.time_ns(),
            'utime_ticks': int(fields[11]), 'stime_ticks': int(fields[12]),
            'threads': int(fields[17]), 'fd_count': len(list((proc / 'fd').iterdir())),
            **memory}


def measure(pid, idle_seconds):
    before = proc_sample(pid)
    time.sleep(idle_seconds)
    after = proc_sample(pid)
    return {'before': before, 'after': after,
            'elapsed_ns': after['monotonic_ns'] - before['monotonic_ns'],
            'idle_cpu_ticks': after['utime_ticks'] + after['stime_ticks'] -
                              before['utime_ticks'] - before['stime_ticks']}


def configure(root, unused_count, front, unused_port):
    key = root / 'key'
    key.write_text(base64.b64encode(bytes(range(16))).decode())
    key.chmod(0o600)
    rules, files, outbounds = [], [], []
    for index in range(unused_count):
        name = f'edge{index}'
        # Every proxy is referenced by a valid reachable port rule. The local
        # direct probe uses an ephemeral port, so none of these rules matches.
        (root / f'{name}.kdl').write_text(
            f'schema-version 2\nkind "predicate"\nrule type="port" value="{index + 1}"\n')
        files.append(f'rule-set "{name}" path="{name}.kdl" format="kdl"')
        rules.append(f'rule action="route" rule-set="{name}" outbound="{name}"')
        outbounds.append(f'''outbound "{name}" type="shadowsocks" {{
 server host="127.0.0.1" port={unused_port}; method "2022-blake3-aes-128-gcm"
 key-file "{key}"; udp-over-tcp "v2"
}}''')
    rules.append('rule action="route" outbound="direct"')
    text = f'''schema-version 1
role "client"
workers 1
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
{chr(10).join(outbounds)}
routing {{ {'; '.join(files)}{' ;' if files else ''}
 tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{ {'; '.join(rules)}; }}
 default-outbound "direct"
}}
'''
    path = root / 'config.kdl'
    path.write_text(text)
    return path, text


def verify_direct(connection, origin, index):
    peer, relay = connection
    header = b'\0\0\0\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', origin.getsockname()[1])
    payload = f'association-{index}'.encode()
    peer.sendto(header + payload, relay)
    received, source = origin.recvfrom(4096)
    if received != payload:
        raise RuntimeError('direct probe payload mismatch')
    origin.sendto(received, source)
    response, _ = peer.recvfrom(4096)
    if response != header + payload:
        raise RuntimeError('direct probe reply mismatch')


def run_configuration(args, count, emit, identity):
    with tempfile.TemporaryDirectory(prefix='nexus-udp-readers-') as directory, \
            socket.socket() as unused, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin:
        root = Path(directory)
        unused.bind(('127.0.0.1', 0))
        unused.listen(32)
        origin.bind(('127.0.0.1', 0))
        origin.settimeout(3)
        if origin.getsockname()[1] <= 16:
            raise RuntimeError('ephemeral probe port overlaps proxy route rules')
        front = free_port()
        config, text = configure(root, count, front, unused.getsockname()[1])
        common = {**identity, 'unused_proxy_outbounds': count, 'workers': 1,
                  'configured_associations': args.associations, 'idle_seconds_requested': args.idle_seconds,
                  'configuration': text, 'configuration_sha256': sha256(config),
                  'probe_port': origin.getsockname()[1], 'unused_upstream_port': unused.getsockname()[1]}
        with nexus_process(str(args.binary), str(config)) as process:
            common['pid'] = process.pid
            time.sleep(.2)
            zero = measure(process.pid, args.idle_seconds)
            emit({**common, 'phase': 'zero', 'associations': 0, **zero})
            with contextlib.ExitStack() as associations:
                for index in range(args.associations):
                    connection = associations.enter_context(udp_client(front))
                    verify_direct(connection, origin, index)
                time.sleep(.2)
                active = measure(process.pid, args.idle_seconds)
                emit({**common, 'phase': 'active', 'associations': args.associations, **active})
                if select.select([unused], [], [], 0)[0]:
                    raise RuntimeError('an unused proxy received a connection')
            baseline_fds = zero['after']['fd_count']
            until = time.monotonic() + 5
            recovered = proc_sample(process.pid)
            while recovered['fd_count'] != baseline_fds and time.monotonic() < until:
                time.sleep(.02)
                recovered = proc_sample(process.pid)
            closed = measure(process.pid, args.idle_seconds)
            restored = closed['before']['fd_count'] == baseline_fds == closed['after']['fd_count']
            emit({**common, 'phase': 'closed', 'associations': 0, 'baseline_fd_count': baseline_fds,
                  'fd_returned_to_baseline': restored, **closed})
            if not restored:
                raise RuntimeError(f'{count} proxy outbounds: FD count did not return to {baseline_fds}')
            if select.select([unused], [], [], 0)[0]:
                raise RuntimeError('an unused proxy received a connection during drain')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--associations', type=int, choices=(16, 32), default=16)
    parser.add_argument('--idle-seconds', type=float, default=1.25)
    parser.add_argument('--outbounds', type=int, nargs='+', default=[0, 1, 4, 16])
    args = parser.parse_args()
    if not 1 <= args.idle_seconds <= 2:
        parser.error('--idle-seconds must be between 1 and 2')
    if any(count < 0 or count > 16 for count in args.outbounds):
        parser.error('--outbounds must be within the production limit 0..16')
    args.binary = args.binary.resolve(strict=True)
    identity = {'binary': str(args.binary), 'binary_sha256': sha256(args.binary),
                'driver_sha256': sha256(Path(__file__)), 'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'),
                'page_size': os.sysconf('SC_PAGE_SIZE'), 'kernel': os.uname().release,
                'method': 'one sample per configuration; direct probe per association; idle process accounting'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as output:
        def emit(record):
            output.write(json.dumps(record, sort_keys=True) + '\n')
            output.flush()
        for count in dict.fromkeys(args.outbounds):
            run_configuration(args, count, emit, identity)
            print(f'unused outbounds={count}: {args.associations} direct associations measured; FD baseline restored', flush=True)


if __name__ == '__main__':
    main()
