#!/usr/bin/env python3
"""Test source rules through real SOCKS and authenticated SS UDP inbounds."""
import base64
import pathlib
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
fixture = pathlib.Path(sys.argv[2]).resolve()

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size-len(data))
        if not part: raise RuntimeError('unexpected EOF')
        data += part
    return data

def ready(proc):
    if not select.select([proc.stdout], [], [], 10)[0]: raise RuntimeError('startup timed out')
    if b'listening' not in proc.stdout.readline(): raise RuntimeError(f'startup failed: {proc.stderr.read()!r}')

def stop(proc):
    if proc.poll() is None: proc.send_signal(signal.SIGTERM)
    _, err = proc.communicate(timeout=10)
    if proc.returncode: raise RuntimeError(f'server exited {proc.returncode}: {err!r}')

with tempfile.TemporaryDirectory(prefix='nexus-source-udp-') as directory:
    root = pathlib.Path(directory)
    key = root/'key'; key.write_text(base64.b64encode(bytes(range(16))).decode()+'\n'); key.chmod(0o600)
    ss_port, socks_port = port(), port()
    client = subprocess.Popen([fixture, str(ss_port), '16', 'source'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    server = None
    try:
        if not select.select([client.stdout], [], [], 5)[0]: raise RuntimeError('fixture startup timeout')
        blocked_port, allowed_port = map(int, client.stdout.readline().split())
        if blocked_port == allowed_port: raise RuntimeError('source port collision')
        rule = root/'rules.kdl'
        rule.write_text(f'''schema-version 2
kind "predicate"
rule type="and" {{
 rule type="source-ip-cidr" value="127.0.0.0/8"
 rule type="source-port" value="{blocked_port}"
 rule type="network" value="udp"
}}
''')
        config = root/'server.kdl'
        config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{
 socks5 "socks" {{ listen host="127.0.0.1" port={socks_port}; authentication "none"; }}
 shadowsocks "ss" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}
}}
outbounds {{ direct "direct"; block "reject"; }}
routing {{ rulesets {{ "rules" path="rules.kdl" format="kdl"; }}; rules {{ - kind="rule-set" value="rules" outbound="reject"; }}; final "direct"; }}
''')
        server = subprocess.Popen(['stdbuf','-oL',binary,'run','--config',config],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        ready(server)
        deadline=time.monotonic()+10
        while True:
            if server.poll() is not None: raise RuntimeError(f'server exited: {server.stderr.read()!r}')
            try:
                with socket.create_connection(('127.0.0.1',socks_port),timeout=.2): break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        client.stdin.write(b'x\n'); client.stdin.flush()
        _, err = client.communicate(timeout=8)
        if client.returncode: raise RuntimeError(f'SS source fixture exit {client.returncode}: {err!r}')
        # Reuse the now-released blocked source port for a SOCKS association.
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as target, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            target.bind(('127.0.0.1',0)); target.settimeout(.4)
            udp.bind(('127.0.0.1',blocked_port)); udp.settimeout(.4)
            with socket.create_connection(('127.0.0.1',socks_port),timeout=3) as control:
                control.sendall(b'\x05\x01\x00')
                if exact(control,2)!=b'\x05\x00': raise RuntimeError('SOCKS greeting')
                control.sendall(b'\x05\x03\x00\x01\x7f\x00\x00\x01'+blocked_port.to_bytes(2,'big'))
                reply=exact(control,10)
                if reply[:4]!=b'\x05\x00\x00\x01': raise RuntimeError(f'SOCKS associate {reply!r}')
                relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],'big'))
                packet=b'\x00\x00\x00\x01\x7f\x00\x00\x01'+target.getsockname()[1].to_bytes(2,'big')+b'blocked'
                udp.sendto(packet,relay)
                try: raise RuntimeError(f'blocked SOCKS target received {target.recvfrom(128)!r}')
                except TimeoutError: pass
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as allowed:
                allowed.bind(('127.0.0.1',0)); allowed.settimeout(2); target.settimeout(2)
                with socket.create_connection(('127.0.0.1',socks_port),timeout=3) as control:
                    control.sendall(b'\x05\x01\x00')
                    if exact(control,2)!=b'\x05\x00': raise RuntimeError('SOCKS allowed greeting')
                    control.sendall(b'\x05\x03\x00\x01\x7f\x00\x00\x01'+allowed.getsockname()[1].to_bytes(2,'big'))
                    reply=exact(control,10)
                    if reply[:4]!=b'\x05\x00\x00\x01': raise RuntimeError('SOCKS allowed associate')
                    relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],'big'))
                    payload=packet[:-7]+b'allowed'
                    allowed.sendto(payload,relay)
                    data, peer=target.recvfrom(128)
                    if data!=b'allowed': raise RuntimeError(f'unexpected allowed payload {data!r}')
                    target.sendto(data,peer)
                    if allowed.recvfrom(128)[0]!=payload: raise RuntimeError('SOCKS allowed reply')
        stop(server); server=None
        print('SOCKS and SS UDP source rules, authenticated rebind and blocked forwarding passed')
    finally:
        if client.poll() is None: client.kill(); client.communicate()
        if server is not None:
            if server.poll() is None: server.kill()
            server.communicate()
