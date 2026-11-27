#!/usr/bin/env python3
"""The default build must reject SRS explicitly before creating listeners."""
import pathlib
import subprocess
import sys
import tempfile
from dns_rule_support import free_port

binary = pathlib.Path(sys.argv[1]).resolve()
fixture = pathlib.Path(sys.argv[2]).resolve()
with tempfile.TemporaryDirectory(prefix='nexus-srs-disabled-') as directory:
    root = pathlib.Path(directory)
    output = root / 'out.kdl'
    convert = subprocess.run([str(binary), 'rule', 'convert', 'srs', 'kdl', str(fixture), str(output)], capture_output=True, text=True, timeout=5)
    if convert.returncode == 0 or 'SRS rule sets require the srs build feature' not in convert.stderr or output.exists():
        raise RuntimeError(f'disabled conversion was not rejected: {convert.stderr}')
    for ordered in (False, True):
        config = root / 'config.kdl'
        rule = ('tcp-program sniff-timeout-ms=100 unknown="skip" { rule action="reject" rule-set="deny" ip-cidr-match-source=#true; }'
                if ordered else 'rules { - kind="rule-set" value="deny" outbound="reject" ip-cidr-match-source=#true; }')
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={free_port()}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rulesets {{ deny path="{fixture}" format="srs"; }}; {rule}; final "direct"; }}
''')
        run = subprocess.run([str(binary), 'run', '--config', str(config)], capture_output=True, text=True, timeout=5)
        if run.returncode == 0 or 'SRS rule sets require the srs build feature' not in run.stderr or 'listening' in run.stdout:
            raise RuntimeError(f'disabled routing was not rejected: {run.stderr}')
    config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={free_port()}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
dns {{ server "a" type="udp" host="127.0.0.1"; rulesets {{ deny path="{fixture}" format="srs"; }};
 rule rule-set="deny" ip-cidr-match-source=#true action="reject"; }}
''')
    run = subprocess.run([str(binary), 'run', '--config', str(config)], capture_output=True, text=True, timeout=5)
    if run.returncode == 0 or 'SRS rule sets require the srs build feature' not in run.stderr or 'listening' in run.stdout:
        raise RuntimeError(f'disabled DNS rule-set was not rejected: {run.stderr}')
    config.write_text(config.read_text().replace('ip-cidr-match-source=#true action="reject"', 'match-response=#true action="respond"'))
    run = subprocess.run([str(binary), 'run', '--config', str(config)], capture_output=True, text=True, timeout=5)
    if run.returncode == 0 or 'DNS response rules are unavailable in this build' not in run.stderr or 'listening' in run.stdout:
        raise RuntimeError(f'disabled DNS response rule was not rejected: {run.stderr}')
    config.write_text(config.read_text().replace('rule rule-set="deny" match-response=#true action="respond"', 'rule action="evaluate" server="a" tag="answer"; rule rule-set="deny" match-response="answer" action="respond"'))
    run = subprocess.run([str(binary), 'run', '--config', str(config)], capture_output=True, text=True, timeout=5)
    if run.returncode == 0 or 'DNS response rules are unavailable in this build' not in run.stderr or 'listening' in run.stdout:
        raise RuntimeError(f'disabled named DNS response was not rejected: {run.stderr}')
print('SRS disabled: conversion, traffic, DNS and response rule sets rejected before output/listening')
