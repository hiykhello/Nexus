#!/usr/bin/env python3
"""A single-key SS inbound does not invent a named authenticated user."""
import base64
import pathlib
import select
import socket
import subprocess
import sys
import tempfile

binary,fixture=(pathlib.Path(arg).resolve() for arg in sys.argv[1:3])
with tempfile.TemporaryDirectory(prefix='nexus-auth-ss-') as directory:
    root=pathlib.Path(directory)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0)); port=probe.getsockname()[1]
    key=root/'key'; key.write_text(base64.b64encode(bytes(range(16))).decode()+'\n'); key.chmod(0o600)
    (root/'rules.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="not" { rule type="auth-user" value="alice"; }\n')
    (root/'config.kdl').write_text(f'''schema-version 1
role "server"
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rule-set "users" path="rules.kdl" format="kdl"; rule kind="rule-set" value="users" outbound="reject"; default-outbound "direct"; }}
''')
    server=subprocess.Popen(['stdbuf','-oL',binary,'run','--config',root/'config.kdl'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        if not select.select([server.stdout],[],[],10)[0] or b'listening' not in server.stdout.readline():
            raise RuntimeError('SS server did not start')
        subprocess.run([fixture,str(port),'16','inbound-allowed'],check=True,timeout=5)
        server.terminate(); _,err=server.communicate(timeout=10)
        if server.returncode: raise RuntimeError(f'shutdown failed: {err!r}')
        print('SS single-key user remains unknown under NOT')
    finally:
        if server.poll() is None: server.kill(); server.communicate()
