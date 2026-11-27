#!/usr/bin/env python3
"""Exercise per-connection QUIC MTU fallback on a shared Hy2 listener."""
import argparse
import contextlib
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import threading
import time

from detour_network import exact, reserve, socks
from dns_rule_support import nexus_process
from hy2_outbound_detour import udp_port
from udp_bind_port_network import certificate


def run(binary, shim, plain):
    payloads = [bytes((i + n) % 256 for i in range(256)) * 512 for n in range(2)]
    errors = []
    with tempfile.TemporaryDirectory(prefix='hy2-mtu-isolation-') as directory:
        root = Path(directory); certificate(root)
        for name, value in (('password', 'test-password'), ('obfs', 'salamander-secret')):
            path = root / name; path.write_text(value + '\n'); path.chmod(0o600)
        port = udp_port('127.0.0.1')
        front = [reserve(), reserve()]
        while front[0] == front[1]: front[1] = reserve()
        quic = '' if plain else f'quic {{ salamander-password-file "{root / "obfs"}"; }}'
        server = root / 'server.kdl'
        server.write_text(f'''schema-version 1
role "server"
workers 1
inbound "edge" type="hysteria2" {{ listen host="127.0.0.1" port={port};
 authentication {{ user "test" password-file="{root / 'password'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
 {quic}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
        wrapper = root / 'server'
        wrapper.write_text(f'''#!/bin/sh
export NEXUS_TEST_HY2_LISTENER_PORT={port}
export LD_PRELOAD={shlex.quote(str(shim))}${{LD_PRELOAD:+:$LD_PRELOAD}}
exec {shlex.quote(str(binary))} "$@"
'''); wrapper.chmod(0o700)
        configs = []
        for index in range(2):
            config = root / f'client{index}.kdl'; configs.append(config)
            config.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front[index]}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{ server host="127.0.0.1" port={port};
 inet4-bind-address "127.0.0.{index + 2}"; udp-fragment #false;
 authentication {{ password-file "{root / 'password'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
 {quic}
}}
routing {{ final "edge"; }}
''')
        with socket.socket() as origin, contextlib.ExitStack() as stack:
            origin.bind(('127.0.0.1', 0)); origin.listen(2); origin.settimeout(10)
            stack.enter_context(nexus_process(str(wrapper), str(server)))
            for config in configs: stack.enter_context(nexus_process(str(binary), str(config)))
            clients = []; threads = []
            def serve(conn):
                try:
                    with conn:
                        conn.settimeout(15); index = exact(conn, 1)[0]
                        conn.sendall(bytes([index]))
                        if exact(conn, 1) != b'G': raise RuntimeError('missing go')
                        conn.sendall(payloads[index]); conn.shutdown(socket.SHUT_WR)
                        if conn.recv(1): raise RuntimeError('missing client FIN')
                except BaseException as error: errors.append(repr(error))
            for index in range(2):
                client = stack.enter_context(socks(front[index], 1, ('127.0.0.1', origin.getsockname()[1]))[0])
                client.settimeout(15); clients.append(client)
                conn, _ = origin.accept(); thread = threading.Thread(target=serve, args=(conn,)); thread.start(); threads.append(thread)
                client.sendall(bytes([index]))
                if exact(client, 1) != bytes([index]): raise RuntimeError('preflight mismatch')
            time.sleep(5)
            subprocess.run(['ip', 'route', 'add', 'local', '127.0.0.2/32', 'dev', 'lo', 'table', 'local', 'mtu', '1280'], check=True)
            print(f'{time.time():.6f} limited server path to 127.0.0.2; 127.0.0.3 remains 1500', flush=True)
            affected_ready = threading.Event()
            def transfer(index):
                try:
                    client = clients[index]; client.sendall(b'G'); client.shutdown(socket.SHUT_WR)
                    first = exact(client, 1)
                    if index == 0: affected_ready.set()
                    if first + exact(client, len(payloads[index]) - 1) != payloads[index] or client.recv(1):
                        raise RuntimeError('response mismatch')
                except BaseException as error:
                    errors.append(repr(error)); affected_ready.set()
            workers = [threading.Thread(target=transfer, args=(index,)) for index in range(2)]
            workers[0].start()
            if not affected_ready.wait(12) or errors: raise RuntimeError(f'affected session did not recover: {errors!r}')
            workers[1].start()
            for worker in workers: worker.join(20)
            for thread in threads: thread.join(20)
            if any(thread.is_alive() for thread in workers + threads) or errors: raise RuntimeError(f'isolation failed: {errors!r}')
            print('both shared-port sessions completed reliable payload and FIN', flush=True)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as check: check.bind(('127.0.0.1', port))
        print('listener port released', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path); parser.add_argument('shim', type=Path)
    parser.add_argument('--plain', action='store_true'); parser.add_argument('--isolated', action='store_true')
    args = parser.parse_args(); binary = args.binary.resolve(strict=True); shim = args.shim.resolve(strict=True)
    if not args.isolated:
        command = ['unshare', '-Urn', 'bash', '-c', 'ip link set lo up && ip link set lo mtu 1500 && exec python3 "$@"',
                   'hy2-mtu-isolation', str(Path(__file__).resolve()), str(binary), str(shim), '--isolated']
        if args.plain: command.append('--plain')
        subprocess.run(command, check=True)
    else: run(binary, shim, args.plain)
