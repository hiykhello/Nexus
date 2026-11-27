#!/usr/bin/env python3
"""Exercise the production CONNECT-UDP inbound with an independent quic-go peer."""
import pathlib
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
    with socket.socket(family, socket.SOCK_DGRAM) as echo:
        echo.bind((host, 0)); echo_port = echo.getsockname()[1]; echo.settimeout(.1)
        with socket.socket(family, socket.SOCK_DGRAM) as reserve:
            reserve.bind((host, 0)); port = reserve.getsockname()[1]
        forbidden = socket.socket(family, socket.SOCK_DGRAM); forbidden.bind((host, 0)); forbidden.settimeout(.2)
        stop = threading.Event()
        errors = []
        def serve():
            while not stop.is_set():
                try:
                    data, source = echo.recvfrom(65535); echo.sendto(data, source)
                except TimeoutError:
                    pass
                except OSError as error:
                    if not stop.is_set(): errors.append(str(error))
                    return
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix='masque-quic-go-') as folder:
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
 allow cidr="{'::1/128' if ipv6 else '127.0.0.0/8'}" first-port={echo_port} last-port={echo_port}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
                process = subprocess.Popen([binary, 'run', '--config', config], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    time.sleep(.5)
                    if process.poll() is not None: raise RuntimeError(f'Nexus failed to start: {process.communicate()}')
                    for mode in ('datagram', 'capsule'):
                        result = subprocess.run([peer, '-family', '6' if ipv6 else '4', '-port', str(port), '-target', str(echo_port), '-cert', cert, '-mode', mode, '-denied-target', str(forbidden.getsockname()[1])], capture_output=True, text=True, timeout=25)
                        if result.returncode: raise RuntimeError(f'{mode} peer failed: {result.stdout} {result.stderr}')
                        print(result.stdout.strip(), flush=True)
                finally:
                    if process.poll() is None: process.send_signal(signal.SIGTERM)
                    out, err = process.communicate(timeout=15)
                    if process.returncode: raise RuntimeError(f'Nexus exit {process.returncode}: {out} {err}')
                try:
                    packet, _ = forbidden.recvfrom(65535)
                    raise RuntimeError(f'forbidden destination received {packet!r}')
                except TimeoutError: pass
                with socket.socket(family, socket.SOCK_DGRAM) as check: check.bind((host, port))
        finally:
            stop.set(); thread.join(3); forbidden.close()
            if thread.is_alive() or errors: raise RuntimeError(f'echo cleanup: {errors}')
