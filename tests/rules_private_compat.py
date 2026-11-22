#!/usr/bin/env python3
"""Compare private-address matching with the pinned sing-box dependency semantics."""
import ipaddress
import pathlib
import random
import subprocess
import sys
import tempfile

fixture = pathlib.Path(sys.argv[1]).resolve()
source = pathlib.Path(__file__).with_name('rules_private_reference.go')
randomizer = random.Random(0x5ab173)
addresses = [str(ipaddress.ip_address(value)) for value in (
    0, 1, 0x09ffffff, 0x0a000000, 0x0affffff, 0x0b000000,
    0x7effffff, 0x7f000000, 0x7fffffff, 0x80000000,
    0xac0fffff, 0xac100000, 0xac1fffff, 0xac200000,
    0xa9fdffff, 0xa9fe0000, 0xa9feffff, 0xa9ff0000,
    0xdfffffff, 0xe0000000, 0xefffffff, 0xf0000000,
)]
addresses += ['::', '::1', '::2', 'fbff:ffff::1', 'fc00::1', 'fdff:ffff::1',
              'fe00::1', 'fe7f:ffff::1', 'fe80::1', 'febf:ffff::1', 'fec0::1', 'ff00::1',
              '::ffff:0.0.0.0', '::ffff:127.0.0.1', '::ffff:192.168.1.1', '::ffff:8.8.8.8']
for _ in range(10000):
    address = randomizer.getrandbits(32)
    addresses.append(str(ipaddress.IPv4Address(address)))
    addresses.append(str(ipaddress.IPv6Address((0xffff << 32) | address)))
    addresses.append(str(ipaddress.IPv6Address(randomizer.getrandbits(128))))
data = '\n'.join(addresses) + '\n'
with tempfile.TemporaryDirectory(prefix='nexus-private-reference-') as directory:
    reference = pathlib.Path(directory) / 'reference'
    subprocess.run(['go', 'build', '-o', reference, source], check=True)
    expected = subprocess.run([reference], input=data, text=True, capture_output=True, check=True).stdout.splitlines()
    actual = subprocess.run([fixture], input=data, text=True, capture_output=True, check=True).stdout.splitlines()
    if len(actual) != len(addresses) or len(expected) != len(addresses):
        raise RuntimeError(f'result length mismatch: {len(addresses)}, {len(actual)}, {len(expected)}')
    for address, left, right in zip(addresses, actual, expected):
        if left != right:
            raise RuntimeError(f'{address}: Nexus={left}, reference={right}')
print(f'{len(addresses)} private-address results match Go reference')
