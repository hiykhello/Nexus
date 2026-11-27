#!/usr/bin/env python3
"""Count actual Snell transports while sending sequential TCP streams."""
import base64
import errno
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from detour_network import exact, reserve, running, socks
from dns_rule_support import Echo, udp_client

binary = Path(sys.argv[1]).resolve(strict=True)
revision = '824dbcfb4dd0a95921840b1737b950cde590241e'
if f'Revision: {revision}' not in subprocess.check_output(['sing-box', 'version'], text=True):
    raise RuntimeError('unexpected sing-box revision')

class Relay:
    def __init__(self, port, destination):
        self.server = socket.socket(); self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('127.0.0.1', port)); self.server.listen(); self.server.settimeout(.1)
        self.destination = destination; self.stop = threading.Event(); self.count = 0; self.threads = []; self.sockets = []
        self.listener = threading.Thread(target=self.accept, daemon=True)
    def accept(self):
        while not self.stop.is_set():
            try: client, _ = self.server.accept()
            except TimeoutError: continue
            except OSError: break
            upstream = socket.create_connection(('127.0.0.1', self.destination), timeout=5)
            self.count += 1; self.sockets.extend((client, upstream))
            def forward(source, target):
                try:
                    while data := source.recv(65536): target.sendall(data)
                except OSError: pass
                finally:
                    try: target.shutdown(socket.SHUT_WR)
                    except OSError: pass
            for source, target in ((client, upstream), (upstream, client)):
                thread = threading.Thread(target=forward, args=(source, target), daemon=True); thread.start(); self.threads.append(thread)
    def __enter__(self): self.listener.start(); return self
    def close_connections(self):
        for sock in self.sockets:
            try: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            sock.close()
    def __exit__(self, *args):
        self.stop.set(); self.server.close(); self.listener.join(2)
        for sock in self.sockets:
            try: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            sock.close()
        for thread in self.threads: thread.join(2)
        if self.listener.is_alive() or any(thread.is_alive() for thread in self.threads): raise RuntimeError('relay did not drain')

with tempfile.TemporaryDirectory(prefix='snell-pool-') as folder:
    root = Path(folder); psk = root/'psk'; psk.write_text('nexus-snell-test\n'); psk.chmod(0o600)
    key = root/'sskey'; password = base64.b64encode(bytes(range(16))).decode(); key.write_text(password); key.chmod(0o600)
    for mode in ('physical', 'tfo', 'direct-tfo', 'detour'):
        for workers in (1, 2):
            front, edge, gateway, lower = reserve(), reserve(), reserve(), reserve()
            box = root/'box.json'; box.write_text(json.dumps({'log': {'level': 'warn'},
                'inbounds': [{'type': 'snell', 'listen': '127.0.0.1', 'listen_port': edge, 'version': 5, 'psk': 'nexus-snell-test', 'obfs_mode': 'http'},
                             {'type': 'shadowsocks', 'listen': '127.0.0.1', 'listen_port': lower, 'method': '2022-blake3-aes-128-gcm', 'password': password}],
                'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}))
            subprocess.run(['sing-box', 'check', '-c', str(box)], check=True, capture_output=True)
            lower_config = f'outbound "lower" type="shadowsocks" {{ server host="127.0.0.1" port={lower}; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}' if mode == 'detour' else ''
            extra = 'detour "lower";' if mode == 'detour' else 'tcp-fast-open #true;' if mode == 'tfo' else 'detour "direct";' if mode == 'direct-tfo' else ''
            direct = 'outbound "direct" type="direct" { tcp-fast-open #true; }' if mode == 'direct-tfo' else 'outbound "direct" type="direct"'
            config = root/'nexus.kdl'; config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
{direct}
{lower_config}
outbound "edge" type="snell" {{ server host="127.0.0.1" port={gateway}; version 4; psk-file "{psk}"; obfs "http"; reuse #true; {extra} }}
routing {{ final "edge"; }}
''')
            payload = bytes(range(251))*100; errors = []; origin_stop = threading.Event()
            with socket.socket() as origin:
                origin.bind(('127.0.0.1', 0)); origin.listen(); origin.settimeout(.2)
                def echo():
                    try:
                        while not origin_stop.is_set():
                            try:
                                conn, _ = origin.accept()
                            except TimeoutError:
                                continue
                            with conn:
                                conn.settimeout(8); data = bytearray()
                                while part := conn.recv(65536): data.extend(part)
                                if bytes(data) != payload: raise RuntimeError('origin payload mismatch')
                                conn.sendall(data); conn.shutdown(socket.SHUT_WR)
                    except BaseException as error: errors.append(repr(error))
                thread = threading.Thread(target=echo, daemon=True); thread.start()
                with running(['sing-box', 'run', '-c', str(box)], edge, root/'box.log'), Relay(gateway, edge) as relay, running([str(binary), 'run', '--config', str(config)], front, root/'nexus.log'):
                    for index in range(32):
                        with socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))[0] as client:
                            client.settimeout(8); client.sendall(payload); client.shutdown(socket.SHUT_WR)
                            if exact(client, len(payload)) != payload or client.recv(1) != b'': raise RuntimeError('TCP response/FIN mismatch')
                        time.sleep(.1)  # allow the worker to finish its session and release its lease
                        if relay.count > workers: raise RuntimeError(f'unexpected Snell transport count {relay.count}, workers={workers}')
                        # Accept is distributed across workers. Warm every worker's pool
                        # so the next request necessarily leases a closed connection.
                        if index >= 5 and relay.count == workers: break
                    else: raise RuntimeError(f'only {relay.count} of {workers} Snell worker pools warmed')
                    # A closed idle connection must fail the committed request;
                    # the pool must not replay it on a fresh transport.
                    old_count = relay.count; relay.close_connections(); time.sleep(.1)
                    try:
                        with socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))[0] as client:
                            client.settimeout(5); client.sendall(b'stale'); client.shutdown(socket.SHUT_WR)
                            if client.recv(1): raise RuntimeError('stale connection returned application data')
                    except OSError as error:
                        if error.errno not in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN): raise
                    except RuntimeError as error:
                        if not str(error).startswith(('SOCKS command failed:', 'unexpected EOF after')): raise
                    if relay.count != old_count: raise RuntimeError('committed request reopened transport')
                    # Each worker may still hold one separately closed idle
                    # transport. A later request must eventually open a fresh
                    # transport and deliver a complete new stream.
                    recovered = False
                    for _ in range(8):
                        before = relay.count
                        try:
                            with socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))[0] as client:
                                client.settimeout(5); client.sendall(payload); client.shutdown(socket.SHUT_WR)
                                recovered = exact(client, len(payload)) == payload and client.recv(1) == b''
                        except OSError as error:
                            if error.errno not in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN): raise
                        except RuntimeError as error:
                            if not str(error).startswith(('SOCKS command failed:', 'unexpected EOF after')): raise
                        if recovered:
                            if relay.count != before + 1: raise RuntimeError('recovery did not open exactly one new transport')
                            break
                        if relay.count != before: raise RuntimeError('failed request reopened transport')
                        time.sleep(.1)
                    if not recovered: raise RuntimeError('new request did not recover after stale connections')
                    with Echo() as udp, udp_client(front) as (client, target):
                        address = b'\x01' + socket.inet_aton('127.0.0.1') + udp.port.to_bytes(2, 'big'); client.sendto(b'\0\0\0'+address+b'udp', target)
                        reply, _ = client.recvfrom(65535)
                        if reply[10:] != b'udp': raise RuntimeError('UDP fallback mismatch')
                origin_stop.set()
                thread.join(8)
                if thread.is_alive() or errors: raise RuntimeError(f'origin failed: {errors!r}')
            print(f'Snell reuse {mode} workers={workers} {index+1} TCP streams and UDP fallback passed', flush=True)
