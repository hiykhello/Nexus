#!/usr/bin/env python3
"""Exercise imported sing-box rule sets through real TCP and UDP routing."""
import base64
import json
import pathlib
import subprocess
import sys
import tempfile
from dns_rule_support import DnsPeer, Echo, datagram_request, free_port, nexus_process, ss_client, stream_request, udp_client

binary = pathlib.Path(sys.argv[1]).resolve()
revision = '824dbcfb4dd0a95921840b1737b950cde590241e'
if f'Revision: {revision}' not in subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError('unexpected sing-box revision')

for ordered in (False, True):
    with tempfile.TemporaryDirectory(prefix='nexus-srs-route-') as directory, DnsPeer() as dns, Echo() as origin:
        root = pathlib.Path(directory)
        source = root / 'rules.json'
        source.write_text(json.dumps({"version": 2, "rules": [{"domain_regex": [r"(^|\.)blocked\.test$"]}]}))
        subprocess.run(['sing-box', 'rule-set', 'compile', str(source), '-o', str(root / 'rules.srs')], check=True)
        source.write_text('{"version":2,"rules":[{"source_ip_cidr":["192.0.2.0/24"],"ip_cidr":["127.0.0.0/8"],"domain_suffix":["source-blocked.test"]}]}')
        subprocess.run(['sing-box', 'rule-set', 'compile', str(source), '-o', str(root / 'source.srs')], check=True)
        for fmt in ('kdl', 'beve'):
            subprocess.run([str(binary), 'rule', 'convert', 'srs', fmt, str(root / 'rules.srs'), str(root / f'converted.{fmt}')], check=True)
        bad = root / 'unsupported.json'
        bad.write_text('{"version":3,"rules":[{"network_type":["wifi"]}]}')
        subprocess.run(['sing-box', 'rule-set', 'compile', str(bad), '-o', str(root / 'unsupported.srs')], check=True)
        failed = subprocess.run([str(binary), 'rule', 'convert', 'srs', 'kdl', str(root / 'unsupported.srs'), str(root / 'bad.kdl')], capture_output=True, text=True)
        if failed.returncode == 0 or 'unsupported SRS condition' not in failed.stderr or (root / 'bad.kdl').exists():
            raise RuntimeError('unsupported SRS condition did not fail conversion')
        upper = root / 'uppercase.json'
        upper.write_text('{"version":2,"rules":[{"domain":["EXAMPLE.test"]}]}')
        subprocess.run(['sing-box', 'rule-set', 'compile', str(upper), '-o', str(root / 'uppercase.srs')], check=True)
        failed = subprocess.run([str(binary), 'rule', 'convert', 'srs', 'kdl', str(root / 'uppercase.srs'), str(root / 'uppercase.kdl')], capture_output=True, text=True)
        if failed.returncode == 0 or 'uppercase' not in failed.stderr or (root / 'uppercase.kdl').exists():
            raise RuntimeError('uppercase SRS domain did not fail conversion')
        key = bytes(range(16))
        (root / 'key').write_text(base64.b64encode(key).decode()); (root / 'key').chmod(0o600)
        front, ss = free_port(), free_port()
        while ss == front:
            ss = free_port()
        rule = ('tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true { rule action="reject" rule-set="deny"; rule action="reject" rule-set="source"; rule action="reject" rule-set="source" ip-cidr-match-source=#true; }'
                if ordered else 'rule kind="rule-set" value="deny" outbound="reject"; rule kind="rule-set" value="source" outbound="reject"; rule kind="rule-set" value="source" outbound="reject" ip-cidr-match-source=#true')
        config = root / 'config.kdl'
        config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ mixed "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
 shadowsocks "ss" {{ listen host="127.0.0.1" port={ss}; method "2022-blake3-aes-128-gcm"; key-file "{root / 'key'}"; }} }}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rule-set "deny" path="rules.srs" format="srs"; rule-set "source" path="source.srs" format="srs"; {rule}; default-outbound "direct"; }}
dns {{ server "a" type="udp" host="127.0.0.1" port={dns.port}; final "a"; strategy "ipv4_only"; }}
''')
        invalid_config = root / 'invalid.kdl'
        invalid_config.write_text(config.read_text().replace('rules.srs', 'unsupported.srs'))
        rejected = subprocess.run([str(binary), 'run', '--config', str(invalid_config)], capture_output=True, text=True, timeout=5)
        if rejected.returncode == 0 or 'unsupported SRS condition' not in rejected.stderr:
            raise RuntimeError(f'unsupported SRS did not reject startup: {rejected.stderr}')
        for bad_config in (config.read_text().replace('ip-cidr-match-source=#true', 'ip-cidr-match-source="true"'),
                           config.read_text().replace('path="source.srs" format="srs"', 'path="source.srs" format="kdl"')):
            invalid_config.write_text(bad_config)
            rejected = subprocess.run([str(binary), 'run', '--config', str(invalid_config)], capture_output=True, text=True, timeout=5)
            if rejected.returncode == 0:
                raise RuntimeError('invalid source matching option accepted')
        with nexus_process(str(binary), str(config), 2), udp_client(front) as socks, ss_client(root, ss, key) as ss_udp:
            stream_request(front, origin.port, 'allowed.test')
            stream_request(front, origin.port, 'blocked.test', success=False)
            stream_request(front, origin.port, 'x.blocked.test', success=False)
            stream_request(front, origin.port, 'source-blocked.test', success=False)
            for client, relay in (socks, ss_udp):
                datagram_request(client, relay, origin.port, 'allowed.test')
                datagram_request(client, relay, origin.port, 'x.blocked.test', success=False)
                datagram_request(client, relay, origin.port, 'source-blocked.test', success=False)
                datagram_request(client, relay, origin.port, 'allowed.test')
            if dns.count('blocked.test', 1) or dns.count('x.blocked.test', 1) or dns.count('source-blocked.test', 1):
                raise RuntimeError('blocked SRS domain unexpectedly reached DNS')
        print(f'SRS {"ordered" if ordered else "legacy"}: TCP, SOCKS UDP and SS UDP pass/reject/recovery passed', flush=True)
