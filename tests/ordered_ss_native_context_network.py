"""Shared SS key retains per-listener route metadata and drains DNS on stop."""
import base64
import contextlib
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from dns_rule_support import DnsPeer, Echo, datagram_request, free_port, nexus_process, ss_client


def main(binary):
    revision = '824dbcfb4dd0a95921840b1737b950cde590241e'
    if f'Revision: {revision}' not in subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError('unexpected sing-box revision')
    with tempfile.TemporaryDirectory() as directory, DnsPeer() as dns, Echo() as echo:
        root = Path(directory); key = bytes(range(16))
        (root / 'key').write_text(base64.b64encode(key).decode()); (root / 'key').chmod(0o600)
        blocked, allowed = free_port(), free_port()
        while blocked == allowed: allowed = free_port()
        (root / 'block.kdl').write_text('''schema-version 2
kind "predicate"
rule type="and" { rule type="inbound" value="blocked"; rule type="source-ip-cidr" value="127.0.0.0/8"; rule type="source-port-range" value="1-65535"; }
''')
        (root / 'slow.kdl').write_text(
            'schema-version 2\nkind "predicate"\nrule type="domain" value="slow.test"\n')
        dns.delays['slow.test',1]=.5
        (root / 'config.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{
 shadowsocks "blocked" {{ listen host="127.0.0.1" port={blocked}; method "2022-blake3-aes-128-gcm"; key-file "{root / 'key'}"; }}
 shadowsocks "allowed" {{ listen host="127.0.0.1" port={allowed}; method "2022-blake3-aes-128-gcm"; key-file "{root / 'key'}"; }}
}}
outbound "direct" type="direct"
dns {{ servers {{ udp "resolver" host="127.0.0.1" port={dns.port}; }}; final "resolver"; strategy "ipv4_only"; disable-cache #true; }}
routing {{
  rulesets {{
      "block" path="block.kdl" format="kdl"
      "slow" path="slow.kdl" format="kdl"
  }}
  tcp-program sniff-timeout-ms=100 unknown="pause" udp=#true {{
    rule action="reject" rule-set="block"
    rule action="route-options" rule-set="slow" connect-timeout-ms=120
    rule action="route-options" rule-set="slow" connect-timeout-ms=1000
    rule action="resolve"
    rule action="route" outbound="direct"
  }}
  final "direct"
}}
''')
        (root / 'one').mkdir(); (root / 'two').mkdir()
        dns.drop.add(('pending.example', 1))
        with nexus_process(binary, str(root / 'config.kdl'), listeners=2) as process, contextlib.ExitStack() as stack:
            blocked_client, blocked_relay = stack.enter_context(ss_client(root / 'one', blocked, key))
            allowed_client, allowed_relay = stack.enter_context(ss_client(root / 'two', allowed, key))
            datagram_request(blocked_client, blocked_relay, echo.port, 'rejected.example', success=False)
            if dns.count('rejected.example', 1): raise RuntimeError('blocked inbound reached DNS')
            datagram_request(allowed_client, allowed_relay, echo.port, 'slow.test', success=False)
            if dns.count('slow.test',1)!=1: raise RuntimeError(f'slow lookup missing: {dns.seen!r}')
            time.sleep(.45)
            datagram_request(allowed_client, allowed_relay, echo.port, 'allowed.example')
            if dns.count('allowed.example', 1) != 1: raise RuntimeError(f'allowed lookup missing: {dns.seen!r}')
            # Leave an authenticated datagram in DNS when the process stops.
            raw = b'pending.example'
            packet = b'\x00\x00\x00\x03' + bytes([len(raw)]) + raw + struct.pack('!H', echo.port) + b'pending'
            allowed_client.sendto(packet, allowed_relay)
            end = time.monotonic() + 3
            while not dns.count('pending.example', 1) and time.monotonic() < end: time.sleep(.01)
            if not dns.count('pending.example', 1): raise RuntimeError(f'pending query missing: {dns.seen!r}')
            started = time.monotonic(); process.terminate(); process.wait(timeout=5)
            if process.returncode or time.monotonic() - started > 3:
                raise RuntimeError(f'pending-query shutdown failed: {process.returncode}')
        print('ordered SS native UDP shared key, per-listener source policy, earlier deadline, recovery and pending DNS shutdown passed')


if __name__ == '__main__': main(sys.argv[1])
