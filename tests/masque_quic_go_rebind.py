#!/usr/bin/env python3
"""Change the server-visible UDP source port while a CONNECT-UDP stream is active."""
import pathlib
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary, peer, cert, key = (pathlib.Path(value).resolve(strict=True) for value in sys.argv[1:5])
for ipv6 in (False, True):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    host = '::1' if ipv6 else '127.0.0.1'
    def udp():
        sock = socket.socket(family, socket.SOCK_DGRAM); sock.bind((host, 0)); return sock
    with udp() as echo, udp() as front, udp() as first:
        with udp() as reserve: port = reserve.getsockname()[1]
        server_addr = (host, port); lock = threading.Lock(); stop = threading.Event()
        state = {'upstream': first, 'client': None, 'error': None, 'new_sends': 0}
        def forward():
            while not stop.is_set():
                with lock: upstream = state['upstream']
                try: ready, _, _ = select.select([echo, front, upstream], [], [], .05)
                except (OSError, ValueError): continue
                for sock in ready:
                    try:
                        data, source = sock.recvfrom(65535)
                        if sock is echo: echo.sendto(data, source)
                        elif sock is front:
                            with lock:
                                state['client'] = source
                                state['upstream'].sendto(data, server_addr)
                                if state['upstream'] is not first: state['new_sends'] += 1
                        else:
                            with lock:
                                if sock is state['upstream'] and state['client'] is not None:
                                    front.sendto(data, state['client'])
                    except OSError as error:
                        if not stop.is_set(): state['error'] = str(error)
        worker = threading.Thread(target=forward, daemon=True); worker.start()
        next_socket = None
        try:
            with tempfile.TemporaryDirectory(prefix='masque-rebind-') as folder:
                root = pathlib.Path(folder); token = root/'token'; token.write_text('approved'); token.chmod(0o600)
                config = root/'config.kdl'
                config.write_text(f'''schema-version 1
role "server"
workers 1
inbound "edge" type="masque" {{
 listen host="{host}" port={port}
 authority "localhost"
 authentication {{ bearer-file "{token}"; }}
 tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
 allow cidr="{'::1/128' if ipv6 else '127.0.0.0/8'}" first-port=1 last-port=65535
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
                server = subprocess.Popen([binary, 'run', '--config', config], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                client = None
                try:
                    time.sleep(.5)
                    if server.poll() is not None: raise RuntimeError(f'Nexus start: {server.communicate()}')
                    client = subprocess.Popen([peer, '-family', '6' if ipv6 else '4', '-port', str(front.getsockname()[1]), '-target', str(echo.getsockname()[1]), '-cert', cert, '-rebind'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if not select.select([client.stdout], [], [], 15)[0] or client.stdout.readline().strip() != 'READY_REBIND':
                        raise RuntimeError('peer did not reach rebind barrier')
                    next_socket = udp()
                    if next_socket.getsockname()[1] == first.getsockname()[1]: raise RuntimeError('source port did not change')
                    with lock: state['upstream'] = next_socket
                    client.stdin.write('continue\n'); client.stdin.flush()
                    out, err = client.communicate(timeout=20)
                    if client.returncode: raise RuntimeError(f'peer exit {client.returncode}: {out} {err}')
                    if not state['new_sends']: raise RuntimeError('no packet sent from rebound source')
                    print(f'IPv{6 if ipv6 else 4}: source UDP port {first.getsockname()[1]} -> {next_socket.getsockname()[1]}, packets={state["new_sends"]}; {out.strip()}', flush=True)
                finally:
                    if client and client.poll() is None: client.kill(); client.communicate()
                    if server.poll() is None: server.send_signal(signal.SIGTERM)
                    out, err = server.communicate(timeout=15)
                    if server.returncode: raise RuntimeError(f'Nexus exit {server.returncode}: {out} {err}')
                with socket.socket(family, socket.SOCK_DGRAM) as check_port: check_port.bind((host, port))
        finally:
            stop.set(); worker.join(3)
            if next_socket: next_socket.close()
            if worker.is_alive() or state['error']: raise RuntimeError(f'relay cleanup: {state["error"]}')
