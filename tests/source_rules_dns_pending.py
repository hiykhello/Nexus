#!/usr/bin/env python3
"""Hold SS UDP DNS while a session changes source or inbound, then stop."""
import base64
import pathlib
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

binary, fixture = map(lambda p: pathlib.Path(p).resolve(), sys.argv[1:3])
inbound_test = '--inbound' in sys.argv[3:]

def line(proc, timeout=8):
    if not select.select([proc.stdout], [], [], timeout)[0]: raise RuntimeError('fixture timeout')
    result=proc.stdout.readline()
    if not result: raise RuntimeError(f'fixture exited: {proc.stderr.read()!r}')
    return result

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def release(dns, query, peer):
    response=query[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+query[12:]
    response+=b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01'
    dns.sendto(response,peer)

with tempfile.TemporaryDirectory(prefix='nexus-source-dns-') as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
    root=pathlib.Path(directory); dns.bind(('127.0.0.1',0)); dns.settimeout(5)
    key=root/'key'; key.write_text(base64.b64encode(bytes(range(16))).decode()+'\n'); key.chmod(0o600)
    for cancel in (False,True):
        ss_port=free_port()
        second_port=free_port()
        while second_port==ss_port: second_port=free_port()
        args=[fixture,str(ss_port),'16','inbound-dns',str(second_port)] if inbound_test else [fixture,str(ss_port),'16','source-dns']
        client=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        server=None
        try:
            blocked,allowed=map(int,line(client).split())
            condition='rule type="inbound" value="ss"' if inbound_test else f'rule type="source-port" value="{blocked}"'
            (root/'rules.kdl').write_text(f'''schema-version 2
kind "predicate"
rule type="and" {{
 {condition}
 rule type="ip-cidr" value="127.0.0.0/8"
}}
''')
            config=root/'server.kdl'
            second_inbound=(f'inbound "second" type="shadowsocks" {{ listen host="127.0.0.1" port={second_port}; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}' if inbound_test else '')
            config.write_text(f'''schema-version 1
role "server"
workers 2
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}
{second_inbound}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ rule-set "rules" path="rules.kdl" format="kdl"; rules {{ - kind="rule-set" value="rules" outbound="reject"; }}; default-outbound "direct"; }}
''')
            server=subprocess.Popen(['stdbuf','-oL',binary,'run','--config',config],stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            if b'listening' not in line(server): raise RuntimeError('server startup')
            client.stdin.write(b'x\n'); client.stdin.flush()
            if line(client)!=b'first\n': raise RuntimeError('first send')
            query,peer=dns.recvfrom(2048)
            if query[12:-4]!=b'\x07pending\x04test\x00' or query[-4:-2]!=b'\x00\x01': raise RuntimeError('unexpected DNS query')
            if cancel:
                server.send_signal(signal.SIGTERM)
                _,err=server.communicate(timeout=5)
                if server.returncode: raise RuntimeError(f'stop failed: {err!r}')
                server=None
                release(dns,query,peer)
                client.stdin.write(b'q\n'); client.stdin.flush()
                _,err=client.communicate(timeout=3)
                if client.returncode: raise RuntimeError(f'late response forwarded after stop: {client.returncode}, {err!r}')
            else:
                client.stdin.write(b'x\n'); client.stdin.flush()
                if line(client)!=b'second\n': raise RuntimeError('second send')
                time.sleep(.2)
                release(dns,query,peer)
                client.stdin.write(b'x\n'); client.stdin.flush()
                _,err=client.communicate(timeout=6)
                if client.returncode: raise RuntimeError(f'pending fixture exit {client.returncode}: {err!r}')
                server.send_signal(signal.SIGTERM); _,err=server.communicate(timeout=5)
                if server.returncode: raise RuntimeError(f'stop failed: {err!r}')
                server=None
        finally:
            if client.poll() is None: client.kill(); client.communicate()
            if server is not None:
                if server.poll() is None: server.kill()
                server.communicate()
print(f'SS UDP pending DNS {"inbound" if inbound_test else "source"} snapshot and shutdown passed')
