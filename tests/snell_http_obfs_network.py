#!/usr/bin/env python3
"""Exercise Snell HTTP obfuscation against the pinned sing-box in both roles."""
import json
import contextlib
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

from detour_network import exact, reserve, running, socks
from dns_rule_support import Echo, udp_client


binary = Path(sys.argv[1]).resolve(strict=True)
fragment = '--fragment' in sys.argv[2:]
revision = '824dbcfb4dd0a95921840b1737b950cde590241e'
if f'Revision: {revision}' not in subprocess.check_output(['sing-box', 'version'], text=True):
    raise RuntimeError('unexpected sing-box revision')


class FragmentRelay:
    def __init__(self, port, target):
        self.socket = socket.socket(); self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('127.0.0.1', port)); self.socket.listen(); self.socket.settimeout(.1)
        self.target = target; self.stopped = threading.Event(); self.threads = []; self.headers = 0
        self.thread = threading.Thread(target=self.accept, daemon=True)

    def __enter__(self):
        self.thread.start(); return self

    def accept(self):
        while not self.stopped.is_set():
            try: client, _ = self.socket.accept()
            except TimeoutError: continue
            except OSError: break
            upstream = socket.create_connection(('127.0.0.1', self.target), timeout=5)
            def run(source, dest):
                try:
                    header = bytearray()
                    while b'\r\n\r\n' not in header:
                        part = source.recv(1024)
                        if not part: return
                        header.extend(part)
                        if len(header) > 16384: raise RuntimeError('relay header too large')
                    end = header.index(b'\r\n\r\n') + 4
                    dest.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    for byte in header[:end]:
                        dest.sendall(bytes((byte,))); time.sleep(.0005)
                    self.headers += 1
                    dest.sendall(header[end:])
                    while part := source.recv(65536): dest.sendall(part)
                except (OSError, TimeoutError): pass
                finally:
                    try: dest.shutdown(socket.SHUT_WR)
                    except OSError: pass
            for source, dest in ((client, upstream), (upstream, client)):
                thread = threading.Thread(target=run, args=(source, dest), daemon=True)
                self.threads.append(thread); thread.start()

    def __exit__(self, *_):
        self.stopped.set(); self.socket.close(); self.thread.join(2)
        for thread in self.threads: thread.join(2)
        if self.thread.is_alive() or any(t.is_alive() for t in self.threads):
            raise RuntimeError('fragment relay did not drain')
        if self.headers < 2: raise RuntimeError('both HTTP headers were not fragmented')


with tempfile.TemporaryDirectory(prefix='snell-http-obfs-') as directory:
    root = Path(directory)
    psk = root / 'psk'
    psk.write_text('snell-http-test\n')
    psk.chmod(0o600)
    for role in ('outbound', 'inbound'):
        for workers in (1, 2):
            front, edge = reserve(), reserve()
            gateway = reserve() if fragment else edge
            config, box = root / 'nexus.kdl', root / 'box.json'
            if role == 'outbound':
                config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="snell" {{ server host="127.0.0.1" port={gateway}; version 4; psk-file "{psk}"; obfs "http"; obfs-host "example.test"; obfs-uri "/hello"; }}
routing {{ final "edge"; }}
''')
                box_config = {'log': {'level': 'warn'},
                    'inbounds': [{'type': 'snell', 'listen': '127.0.0.1', 'listen_port': edge, 'version': 5, 'psk': 'snell-http-test', 'obfs_mode': 'http'}],
                    'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}
                first = ['sing-box', 'run', '-c', str(box)]
                second = [str(binary), 'run', '--config', str(config)]
                first_port, second_port = edge, front
            else:
                config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbound "edge" type="snell" {{ listen host="127.0.0.1" port={edge}; version 5; psk-file "{psk}"; replay-window-seconds 60; obfs "http"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
                box_config = {'log': {'level': 'warn'},
                    'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': front}],
                    'outbounds': [{'type': 'snell', 'tag': 'edge', 'server': '127.0.0.1', 'server_port': gateway, 'version': 4, 'psk': 'snell-http-test', 'obfs_mode': 'http', 'obfs_host': 'example.test'}],
                    'route': {'final': 'edge'}}
                first = [str(binary), 'run', '--config', str(config)]
                second = ['sing-box', 'run', '-c', str(box)]
                first_port, second_port = edge, front
            box.write_text(json.dumps(box_config))
            subprocess.run(['sing-box', 'check', '-c', str(box)], check=True, capture_output=True)
            errors = []
            with socket.socket() as origin:
                origin.bind(('127.0.0.1', 0)); origin.listen(); origin.settimeout(8)
                payloads = (b"small", bytes(range(251)) * 500)
                def serve():
                    try:
                        for payload in payloads:
                            with origin.accept()[0] as conn:
                                conn.settimeout(8)
                                data = exact(conn, len(payload))
                                if data != payload: raise RuntimeError('origin payload mismatch')
                                conn.sendall(data)
                    except BaseException as error: errors.append(repr(error))
                thread = threading.Thread(target=serve); thread.start()
                try:
                    with (FragmentRelay(gateway, edge) if fragment else contextlib.nullcontext()), running(first, first_port, root / 'first.log'), running(second, second_port, root / 'second.log'):
                        for payload in payloads:
                            with socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))[0] as client:
                                client.settimeout(8)
                                client.sendall(payload[:3])
                                if fragment: time.sleep(.02)
                                client.sendall(payload[3:])
                                if exact(client, len(payload)) != payload: raise RuntimeError('TCP reply mismatch')
                        with Echo() as echo, udp_client(front) as (client, relay):
                            address = b'\x01' + socket.inet_aton('127.0.0.1') + echo.port.to_bytes(2, 'big')
                            # The pinned sing-snell v4 client rejects an IPv4
                            # response with an empty payload as too short.
                            payloads = (b'', b'hello', bytes(range(256)) * 4) if role == 'outbound' else (b'x', b'hello', bytes(range(256)) * 4)
                            for data in payloads:
                                client.sendto(b'\0\0\0' + address + data, relay)
                                reply, _ = client.recvfrom(65535)
                                if reply[10:] != data: raise RuntimeError('UDP reply mismatch')
                        if role == 'inbound':
                            with socket.create_connection(('127.0.0.1', edge), timeout=5) as invalid:
                                invalid.settimeout(5)
                                try: invalid.sendall(b'X' * 16385)
                                except (BrokenPipeError, ConnectionResetError): pass
                                try:
                                    if invalid.recv(1): raise RuntimeError('oversize obfs header unexpectedly accepted')
                                except ConnectionResetError: pass
                finally:
                    thread.join(timeout=8)
                if thread.is_alive() or errors: raise RuntimeError(f'origin failed: {errors!r}')
            print(f'Snell HTTP obfs {role} workers={workers} fragmented={fragment} 5-byte and 125500-byte TCP/UDP passed', flush=True)
