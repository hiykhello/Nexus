#!/usr/bin/env python3
"""Measure the isolated Hy2/QUIC candidate with real UDP and optional loss."""
import argparse
import heapq
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tests'))
from quic_udp_network import credential, ready


def pair(binary, cert, key, family, backend, rate, loss, drop_every, switch, delay_ms, total, min_acks, drop_over, expect_probe_loss, normal, reorder_every, reorder_ms, expect_spurious, expect_ack_only, unidirectional):
    af, host = (socket.AF_INET6, '::1') if family == '6' else (socket.AF_INET, '127.0.0.1')
    processes = []
    relay = None
    thread = None
    stop = threading.Event()
    counts = {'forwarded': 0, 'dropped': 0, 'reordered': 0, 'reordered_delivered': 0}
    started = time.monotonic()
    try:
        if normal: os.environ.pop('NEXUS_TEST_BRUTAL', None)
        else: os.environ['NEXUS_TEST_BRUTAL'] = str(rate)
        if unidirectional: os.environ['NEXUS_TEST_UNIDIRECTIONAL'] = '1'
        if switch: os.environ['NEXUS_TEST_SWITCH'] = '1'
        server, port, sout = ready([binary, 'server', family, '0', cert, key, '0x0403', backend, str(total)])
        processes.append(server)
        target = port
        if loss or delay_ms or drop_over or reorder_every:
            relay = socket.socket(af, socket.SOCK_DGRAM)
            relay.bind((host, 0)); relay.settimeout(.001); target = relay.getsockname()[1]
            def forward():
                client = None; count = 0; reorder_count = 0; beginning = time.monotonic(); queue = []; sequence = 0
                while not stop.is_set():
                    try:
                        packet, source = relay.recvfrom(65535)
                        from_server = source[1] == port
                        if not from_server: client = source
                        peer = client if from_server else (host, port)
                        drop = bool(drop_over and len(packet) > drop_over)
                        if loss and time.monotonic() - beginning > .5 and packet and not (packet[0] & 0x80):
                            count += 1
                            drop = drop or count % drop_every == 0
                        if drop: counts['dropped'] += 1
                        elif peer is not None:
                            sequence += 1
                            delayed = False
                            if reorder_every and time.monotonic() - beginning > .5 and packet and not (packet[0] & 0x80):
                                reorder_count += 1
                                delayed = reorder_count % reorder_every == 0
                            if delayed: counts['reordered'] += 1
                            heapq.heappush(queue, (time.monotonic() + (delay_ms + (reorder_ms if delayed else 0)) / 1000, sequence, packet, peer, delayed))
                    except TimeoutError: pass
                    while queue and queue[0][0] <= time.monotonic():
                        _, _, packet, peer, delayed = heapq.heappop(queue)
                        relay.sendto(packet, peer); counts['forwarded'] += 1
                        if delayed: counts['reordered_delivered'] += 1
            thread = threading.Thread(target=forward); thread.start()
        client, _, cout = ready([binary, 'client', family, str(target), cert, key, '0x0403', backend, str(total)])
        processes.append(client)
        co, ce = client.communicate(timeout=35)
        so, se = server.communicate(timeout=35)
        result = {'family': family, 'backend': backend, 'bps': rate, 'loss': loss, 'delay_ms': delay_ms, 'drop_over': drop_over,
                  'client_exit': client.returncode, 'server_exit': server.returncode,
                  'client': cout + co, 'server': sout + so, 'client_error': ce, 'server_error': se,
                  'elapsed': time.monotonic() - started, **counts}
        if client.returncode or server.returncode:
            raise RuntimeError(json.dumps(result, indent=2))
        if loss and not counts['dropped']: raise RuntimeError('loss proxy did not drop a packet')
        if drop_over and not counts['dropped']: raise RuntimeError('size filter did not drop a packet')
        if reorder_every and not counts['reordered_delivered']: raise RuntimeError('relay did not deliver any reordered packet')
        if normal: return result
        if switch:
            changes = []
            for role in ('client', 'server'):
                events = re.findall(r'SWITCH role=\w+ stage=(\d+) flight=(\d+) old_rate=(\d+) ms=(\d+)', result[role])
                if len(events) != 2 or [int(event[0]) for event in events] != [1, 2]:
                    raise RuntimeError(f'{role}: unexpected switches: {events!r}')
                if not rate <= int(events[0][2]) <= rate * 5 // 4 or not 2000000 <= int(events[1][2]) <= 2500000:
                    raise RuntimeError(f'{role}: invalid previous rates: {events!r}')
                changes.append([list(map(int, event)) for event in events])
            result['switches'] = changes
            if delay_ms and not all(any(event[1] for event in role) for role in changes):
                raise RuntimeError(f'switch did not observe in-flight data in both directions: {changes!r}')
            return result
        if 'BRUTAL role=client' not in result['client'] or 'BRUTAL role=server' not in result['server']:
            raise RuntimeError(json.dumps(result, indent=2))
        observed = []
        for role in ('client', 'server'):
            match = re.search(r'BRUTAL role=\w+ ms=(\d+) cwnd=(\d+) rate=(\d+) packets=(\d+) loss_total=(\d+) acks=(\d+) losses=(\d+)', result[role])
            if not match: raise RuntimeError(f'{role}: missing controller statistics')
            ms, cwnd, actual_rate, packets, lost, acked, sampled_loss = map(int, match.groups())
            if (cwnd < 1200 or not rate <= actual_rate <= rate * 5 // 4 or
                (not (unidirectional and role == 'server') and (packets < min_acks or acked < min_acks))):
                raise RuntimeError(f'{role}: unexpected controller statistics: {match.group()}')
            if not loss and not (unidirectional and role == 'server') and ms < 1000 * total / rate * .65:
                raise RuntimeError(f'{role}: transfer too fast for pacing: {ms} ms')
            observed.append({'ms': ms, 'cwnd': cwnd, 'rate': actual_rate, 'packets': packets,
                             'lost': lost, 'acked': acked, 'sampled_loss': sampled_loss})
        if loss and not sum(item['sampled_loss'] for item in observed):
            raise RuntimeError('no dropped packet was registered by the Brutal controller')
        if reorder_every and not sum(item['sampled_loss'] for item in observed):
            raise RuntimeError('no reordered packet was registered as lost')
        if expect_probe_loss and (not sum(item['sampled_loss'] for item in observed) or
                                  sum(item['lost'] for item in observed)):
            raise RuntimeError(f'expected probe-only losses in Brutal samples: {observed!r}')
        if expect_spurious or expect_ack_only:
            instrumentation = []
            for role in ('client', 'server'):
                match = re.search(r'BRUTAL_OBSERVE role=\w+ late_acks=(\d+) ack_only_bytes=(\d+)', result[role])
                if not match: raise RuntimeError(f'{role}: missing observation counters')
                instrumentation.append(list(map(int, match.groups())))
            if expect_spurious and not sum(item[0] for item in instrumentation):
                raise RuntimeError(f'no late ACK was dispatched: {instrumentation!r}')
            if expect_ack_only and not sum(item[1] for item in instrumentation):
                raise RuntimeError(f'no ACK-only packet was accounted: {instrumentation!r}')
            result['instrumentation'] = instrumentation
        result['controller'] = observed
        return result
    finally:
        stop.set()
        if thread: thread.join(2)
        if relay: relay.close()
        for process in processes:
            if process.poll() is None: process.kill(); process.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--rate', type=int, default=500000)
    parser.add_argument('--family', choices=('4', '6'), default='4')
    parser.add_argument('--backend', choices=('0', '1'), default='0')
    parser.add_argument('--loss', action='store_true')
    parser.add_argument('--drop-every', type=int, default=35)
    parser.add_argument('--switch', action='store_true')
    parser.add_argument('--delay-ms', type=int, default=0, help='one-way delay in the UDP relay')
    parser.add_argument('--total', type=int, default=1048576)
    parser.add_argument('--min-acks', type=int, default=50, help='minimum sent and acknowledged packets per endpoint')
    parser.add_argument('--drop-over', type=int, default=0, help='drop UDP packets larger than this size; zero disables')
    parser.add_argument('--expect-probe-loss', action='store_true', help='require sampled losses but no ordinary native losses')
    parser.add_argument('--normal', action='store_true', help='leave native congestion control in place')
    parser.add_argument('--reorder-every', type=int, default=0, help='delay every Nth short-header packet after warmup')
    parser.add_argument('--reorder-ms', type=int, default=100, help='extra delay for reordered packets')
    parser.add_argument('--expect-spurious', action='store_true', help='require an observed late ACK in the instrumented candidate')
    parser.add_argument('--expect-ack-only', action='store_true', help='require ACK-only packet accounting in the instrumented candidate')
    parser.add_argument('--unidirectional', action='store_true', help='client sends data; server sends only a FIN')
    args = parser.parse_args()
    if not 1 <= args.total <= 1048576: parser.error('--total must be between 1 and 1048576')
    if args.min_acks < 1: parser.error('--min-acks must be positive')
    if args.drop_over and args.drop_over < 1200: parser.error('--drop-over must be zero or at least 1200')
    if args.expect_probe_loss and (not args.drop_over or args.loss): parser.error('--expect-probe-loss requires --drop-over without --loss')
    if args.normal and (args.switch or args.expect_probe_loss): parser.error('--normal cannot use Brutal assertions or switching')
    if (args.expect_spurious or args.expect_ack_only) and (args.normal or args.switch): parser.error('observation requires an active Brutal controller')
    if args.expect_spurious and not args.reorder_every: parser.error('--expect-spurious requires --reorder-every')
    if args.unidirectional and args.switch: parser.error('--unidirectional cannot test controller switching')
    if args.reorder_every == 1 or args.reorder_every < 0: parser.error('--reorder-every must be zero or at least 2')
    if not 1 <= args.reorder_ms <= 1000: parser.error('--reorder-ms must be between 1 and 1000')
    if args.drop_every < 2: parser.error('--drop-every must be at least 2')
    if not 0 <= args.delay_ms <= 1000: parser.error('--delay-ms must be between 0 and 1000')
    with tempfile.TemporaryDirectory(prefix='hy2-brutal-network-') as temp:
        cert, key = credential(Path(temp), 'p256', 'EC', ['-pkeyopt', 'ec_paramgen_curve:P-256'])
        print(json.dumps(pair(str(args.binary.resolve(strict=True)), cert, key, args.family, args.backend, args.rate, args.loss, args.drop_every, args.switch, args.delay_ms, args.total, args.min_acks, args.drop_over, args.expect_probe_loss, args.normal, args.reorder_every, args.reorder_ms, args.expect_spurious, args.expect_ack_only, args.unidirectional), indent=2))
