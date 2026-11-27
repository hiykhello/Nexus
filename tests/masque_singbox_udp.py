#!/usr/bin/env python3
"""Use the pinned sing-box HTTP/3 outbound to reach a UDP echo via Nexus."""
import json
import pathlib
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dns_rule_support import udp_client
from detour_network import reserve

binary, cert, key = (pathlib.Path(value).resolve(strict=True) for value in sys.argv[1:4])
revision='824dbcfb4dd0a95921840b1737b950cde590241e'
if f'Revision: {revision}' not in subprocess.check_output(['sing-box','version'], text=True):
    raise RuntimeError('unexpected sing-box revision')
for ipv6 in (False, True):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    host = '::1' if ipv6 else '127.0.0.1'
    with socket.socket(family,socket.SOCK_DGRAM) as echo:
        echo.bind((host,0)); echo.settimeout(.1); echo_port=echo.getsockname()[1]
        with socket.socket(family,socket.SOCK_DGRAM) as check:
            check.bind((host,0)); edge_port=check.getsockname()[1]
        front=reserve(); stop=threading.Event(); errors=[]
        def serve():
            while not stop.is_set():
                try:
                    data,addr=echo.recvfrom(65535); echo.sendto(data,addr)
                except TimeoutError: pass
                except OSError as exc:
                    if not stop.is_set(): errors.append(str(exc))
                    return
        worker=threading.Thread(target=serve,daemon=True);worker.start()
        try:
            with tempfile.TemporaryDirectory(prefix='masque-singbox-') as folder:
                root=pathlib.Path(folder); token=root/'token';token.write_text('approved');token.chmod(0o600)
                cfg=root/'nexus.kdl';authority=f'[{host}]:{edge_port}' if ipv6 else f'{host}:{edge_port}'
                cfg.write_text(f'''schema-version 1
role "server"
workers 1
inbound "edge" type="masque" {{
 listen host="{host}" port={edge_port}
 authority "{authority}"
 authentication {{ bearer-file "{token}"; }}
 tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
 allow cidr="{'::1/128' if ipv6 else '127.0.0.0/8'}" first-port=1 last-port=65535
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
                box_cfg=root/'singbox.json';box_cfg.write_text(json.dumps({'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':front}], 'outbounds':[{'type':'http','tag':'edge','server':host,'server_port':edge_port,'version':3,'disable_version_fallback':True,'headers':{'Proxy-Authorization':'Bearer approved'},'tls':{'enabled':True,'server_name':'localhost','certificate_path':str(cert)}}], 'route':{'final':'edge'}}))
                nexus=subprocess.Popen([binary,'run','--config',cfg],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                box=None
                try:
                    time.sleep(.4)
                    if nexus.poll() is not None: raise RuntimeError(f'Nexus startup: {nexus.communicate()}')
                    box=subprocess.Popen(['sing-box','run','-c',box_cfg],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    deadline=time.monotonic()+8
                    while True:
                        if box.poll() is not None: raise RuntimeError(f'sing-box startup: {box.communicate()}')
                        try:
                            with socket.create_connection(('127.0.0.1',front),timeout=.1):break
                        except OSError:
                            if time.monotonic()>=deadline:raise
                            time.sleep(.02)
                    with udp_client(front) as (client,relay):
                        client.settimeout(10)
                        address=socket.inet_pton(family,host)
                        prefix=b'\x00\x00\x00'+(b'\x04' if ipv6 else b'\x01')+address+struct.pack('!H',echo_port)
                        for i in range(2):
                            payload=f'singbox-{i}'.encode();client.sendto(prefix+payload,relay)
                            packet,_=client.recvfrom(65535)
                            if not packet.endswith(payload):raise RuntimeError(f'UDP response mismatch: {packet!r}')
                    print(f'sing-box HTTP/3 CONNECT-UDP IPv{6 if ipv6 else 4}: two UDP echoes passed',flush=True)
                finally:
                    for proc in (box,nexus):
                        if proc is None:continue
                        if proc.poll() is None:proc.send_signal(signal.SIGTERM)
                        out,err=proc.communicate(timeout=15)
                        if proc.returncode:raise RuntimeError(f'process exit {proc.returncode}: {out} {err}')
                with socket.socket(family,socket.SOCK_DGRAM) as check:check.bind((host,edge_port))
        finally:
            stop.set();worker.join(3)
            if worker.is_alive() or errors:raise RuntimeError(f'echo cleanup: {errors}')
