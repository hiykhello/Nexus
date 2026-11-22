#!/usr/bin/env python3
"""Production-style candidate CLI against the pinned sing-box in both roles."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tests'))
from detour_network import exact, reserve, socks
from dns_rule_support import nexus_process, proxy_client
from hy2_outbound_detour import udp_port
from hy2_outbound_singbox import REVISION
from udp_bind_port_network import certificate

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
parser.add_argument('--family', choices=('4', '6'), default='4')
args = parser.parse_args()
binary = args.binary.resolve(strict=True)
if f'Revision: {REVISION}' not in subprocess.check_output(['sing-box', 'version'], text=True): raise RuntimeError('unexpected sing-box revision')
host = '::1' if args.family == '6' else '127.0.0.1'
with tempfile.TemporaryDirectory(prefix='hy2-brutal-singbox-') as directory:
    root = Path(directory); certificate(root)
    password = root / 'password'; password.write_text('test-password\n'); password.chmod(0o600)
    port, front = udp_port(host), reserve()
    tls_server = {'enabled': True, 'certificate_path': str(root/'cert'), 'key_path': str(root/'key'), 'alpn': ['h3']}
    tls_client = {'enabled': True, 'server_name': 'localhost', 'certificate_path': str(root/'cert'), 'alpn': ['h3']}
    config = root/'nexus.kdl'; box_config = root/'box.json'
    payload = bytes(range(256)) * 1024
    for role in ('client', 'server'):
        with socket.socket() as origin:
            origin.bind(('127.0.0.1', 0)); origin.listen(1); origin.settimeout(10)
            errors = []
            def serve():
                try:
                    with origin.accept()[0] as conn:
                        conn.settimeout(10)
                        if exact(conn, len(payload)) != payload: raise RuntimeError('origin upload mismatch')
                        conn.sendall(payload); conn.shutdown(socket.SHUT_WR)
                except BaseException as error: errors.append(repr(error))
            thread = threading.Thread(target=serve); thread.start()
            box = None
            try:
                if role == 'client':
                    box_config.write_text(json.dumps({'log': {'level':'warn'}, 'inbounds': [{'type':'hysteria2','listen':host,'listen_port':port,
                        'users':[{'password':'test-password'}], 'down_mbps': 3, 'tls':tls_server}], 'outbounds':[{'type':'direct','tag':'direct'}], 'route':{'final':'direct'}}))
                    box = subprocess.Popen(['sing-box','run','-c',str(box_config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    time.sleep(.2)
                    if box.poll() is not None: raise RuntimeError(f'sing-box failed: {box.communicate()}')
                    config.write_text(f'''schema-version 1
role "client"
workers 1
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{ server host="{host}" port={port}; authentication {{ password-file "{password}"; }}
 tls {{ server-name "localhost"; ca-file "{root/'cert'}"; verify #true; }}
 quic {{ send-bps 600000; receive-bps 500000; }} }}
routing {{ default-outbound "edge"; }}
''')
                    context = nexus_process(str(binary), str(config))
                else:
                    config.write_text(f'''schema-version 1
role "server"
workers 1
inbound "edge" type="hysteria2" {{ listen host="{host}" port={port}; authentication {{ user "test" password-file="{password}"; }}
 tls {{ certificate-file "{root/'cert'}"; private-key-file "{root/'key'}"; }}
 quic {{ send-bps 400000; receive-bps 300000; }} }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
                    context = nexus_process(str(binary), str(config))
                with context:
                    if role == 'server':
                        peer = {'type':'hysteria2','server':host,'server_port':port,'password':'test-password',
                                'up_mbps': 6,'down_mbps': 6,'tls':tls_client}
                        with proxy_client(root, peer) as socks_port:
                            deadline=time.monotonic()+5
                            while True:
                                try:
                                    with socket.create_connection(('127.0.0.1',socks_port),timeout=.2): pass
                                    break
                                except ConnectionRefusedError:
                                    if time.monotonic()>=deadline: raise
                                    time.sleep(.02)
                            with socks(socks_port,1,('127.0.0.1',origin.getsockname()[1]))[0] as stream:
                                stream.settimeout(10); start=time.monotonic();stream.sendall(payload)
                                if exact(stream,len(payload)) != payload: raise RuntimeError('download mismatch')
                                elapsed=time.monotonic()-start
                    else:
                        with socks(front,1,('127.0.0.1',origin.getsockname()[1]))[0] as stream:
                            stream.settimeout(10);start=time.monotonic();stream.sendall(payload)
                            if exact(stream,len(payload)) != payload: raise RuntimeError('download mismatch')
                            elapsed=time.monotonic()-start
                if elapsed < .4: raise RuntimeError(f'fixed bandwidth did not pace: {elapsed:.3f}s')
                print(f'IPv{args.family} Nexus {role} vs fixed sing-box: complete 256 KiB each way in {elapsed:.3f}s', flush=True)
            finally:
                if box:
                    if box.poll() is None: box.terminate()
                    _, stderr = box.communicate(timeout=5)
                    if box.returncode: errors.append(f'sing-box exit {box.returncode}: {stderr!r}')
                thread.join(12)
            if thread.is_alive() or errors: raise RuntimeError(f'peer errors: {errors!r}')
