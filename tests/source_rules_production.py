#!/usr/bin/env python3
"""Ensure nested source rules are accepted by ordinary production graphs."""
import base64
import pathlib
import select
import signal
import socket
import subprocess
import sys
import tempfile

binary=pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='nexus-source-production-') as directory:
    root=pathlib.Path(directory)
    (root/'rules.kdl').write_text('''schema-version 2
kind "predicate"
rule type="not" { rule type="source-port" value="5000"; }
''')
    key=root/'key'; key.write_text(base64.b64encode(bytes(range(16))).decode()+'\n'); key.chmod(0o600)
    for inbound in ('socks5','shadowsocks'):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
        settings='authentication "none";' if inbound=='socks5' else f'method "2022-blake3-aes-128-gcm"; key-file "{key}";'
        config=root/'config.kdl'
        config.write_text(f'''schema-version 1
role "server"
inbound "in" type="{inbound}" {{ listen host="127.0.0.1" port={port}; {settings} }}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rulesets {{ "rules" path="rules.kdl" format="kdl"; }}; rules {{ - rule-set="rules" to="reject"; }}; final "direct"; }}
''')
        proc=subprocess.Popen(['stdbuf','-oL',binary,'run','--config',config],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            ready=select.select([proc.stdout],[],[],10)[0]
            if not ready or b'listening' not in proc.stdout.readline():
                raise RuntimeError(f'{inbound}: failed to start with source rule')
            proc.send_signal(signal.SIGTERM)
            _,err=proc.communicate(timeout=10)
            if proc.returncode: raise RuntimeError(f'{inbound}: exited {proc.returncode}: {err!r}')
        finally:
            if proc.poll() is None: proc.kill(); proc.communicate()
print('production SOCKS and SS nested source rule configuration accepted')
