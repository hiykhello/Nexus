#!/usr/bin/env python3
"""Exercise the full message race executor against two real DNS peers."""
import pathlib
import errno
import subprocess
import sys
import time
from dns_rule_support import DnsPeer

binary = pathlib.Path(sys.argv[1]).resolve()
def peer():
    for attempt in range(10):
        try:
            return DnsPeer()
        except OSError as error:
            if error.errno != errno.EADDRINUSE or attempt == 9:
                raise

for backend in ('epoll', 'uring'):
    for scenario in ('race', 'miss', 'fail', 'race-route', 'route', 'route-ready', 'timeout', 'ecs', 'cancel'):
        with peer() as slow, peer() as fast:
            timing = {}
            if scenario in ('race', 'timeout', 'ecs', 'cancel'):
                slow.drop.add(('owner.test', 1))
                if scenario == 'cancel':
                    fast.drop.add(('owner.test', 1))
            elif scenario in ('miss', 'fail'):
                slow.delays['owner.test', 1] = .15
                reply = fast.reply
                def nxdomain(packet, transport):
                    response = reply(packet, transport)
                    return response[:3] + bytes([response[3] | 3]) + response[4:]
                if scenario == 'miss':
                    fast.reply = nxdomain
                else:
                    def malformed(packet, transport):
                        response = reply(packet, transport)
                        # A valid envelope carrying an unsolicited ECS is a
                        # protocol error rather than an ignored short packet.
                        return response[:10] + b'\0\1' + response[12:] + bytes.fromhex('00002904d000000000000b0008000700011800c00002')
                    fast.reply = malformed
            elif scenario == 'race-route':
                pass
            else:
                slow.delays['owner.test', 1] = .3 if scenario == 'route-ready' else .15
                fast.delays['owner.test', 1] = .05 if scenario == 'route-ready' else .3
                reply = slow.reply
                def nxdomain(packet, transport):
                    response = reply(packet, transport)
                    timing['slow_finished'] = time.monotonic()
                    return response[:3] + bytes([response[3] | 3]) + response[4:]
                slow.reply = nxdomain
                fast_reply = fast.reply
                def record_fast(packet, transport):
                    timing['fast_started'] = time.monotonic()
                    return fast_reply(packet, transport)
                fast.reply = record_fast
            result = subprocess.run([str(binary), str(slow.port), str(fast.port), backend, scenario], capture_output=True, timeout=8)
            if result.returncode == 77:
                print(f'{backend}: unavailable')
                break
            if result.returncode or slow.count('owner.test', 1) != 1 or (scenario != 'timeout' and fast.count('owner.test', 1) != 1):
                raise RuntimeError(f'{backend}/{scenario}: exit={result.returncode} stderr={result.stderr!r} slow={slow.seen!r} fast={fast.seen!r}')
            if scenario in ('route', 'route-ready') and not timing['fast_started'] < timing['slow_finished']:
                raise RuntimeError(f'{backend}/{scenario}: speculative route did not start before the race settled: {timing}')
            print(f'{backend}/{scenario}: passed')
