#!/usr/bin/env python3
"""Real address-race slots retain the winning upstream for CNAME follow-up."""
import pathlib
import struct
import subprocess
import sys
from dns_rule_support import DnsPeer, question, wire_name

binary = pathlib.Path(sys.argv[1]).resolve()
production = 'proxy-address' in binary.name or 'production' in binary.name
for backend in ('epoll', 'uring'):
    for scenario in ('race', 'route', 'timeout', 'cancel', 'ttl') + (('dual', 'dual-mismatch') if production else ()):
        with DnsPeer() as slow, DnsPeer() as fast:
            if scenario != 'route':
                slow.drop.add(('alias.test', 1))
                if scenario.startswith('dual'):
                    slow.drop.add(('alias.test', 28))
            else:
                slow.delays['alias.test', 1] = .15
                reply = slow.reply
                def miss(packet, transport):
                    response = reply(packet, transport)
                    return response[:3] + bytes([response[3] | 3]) + response[4:]
                slow.reply = miss
            if scenario == 'ttl':
                fast.delays['target.test', 1] = .4
            if scenario == 'cancel':
                fast.drop.add(('alias.test', 1))
            else:
                original = fast.reply
                def alias(packet, transport):
                    name, kind, end = question(packet)
                    if name != 'alias.test':
                        return original(packet, transport)
                    fast.seen.append((name, kind, transport))
                    cname = wire_name('other.test' if scenario == 'dual-mismatch' and kind == 28 else 'target.test')
                    rr = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 60, len(cname)) + cname
                    return packet[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + packet[12:end] + rr
                fast.reply = alias
            result = subprocess.run([str(binary), str(slow.port), str(fast.port), backend, scenario], capture_output=True, timeout=8)
            if result.returncode == 77:
                print(f'{backend}: unavailable'); break
            expected = slow.count('alias.test', 1) == 1 and (scenario == 'timeout' or fast.count('alias.test', 1) == 1)
            if scenario in ('race', 'route', 'ttl'):
                expected = expected and fast.count('target.test', 1) == 1 and slow.count('target.test', 1) == 0
            if scenario.startswith('dual'):
                expected = expected and slow.count('alias.test', 28) == 1 and fast.count('alias.test', 28) == 1 and \
                    fast.count('target.test', 1) == 1 and fast.count('other.test' if scenario == 'dual-mismatch' else 'target.test', 28) == 1
            if result.returncode or not expected:
                raise RuntimeError(f'{backend}/{scenario}: exit={result.returncode} stderr={result.stderr!r} slow={slow.seen!r} fast={fast.seen!r}')
            print(f'{backend}/{scenario}: passed')
