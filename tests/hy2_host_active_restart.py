#!/usr/bin/env python3
"""Stop and restart a production Hy2 host with a live TCP stream."""
import argparse
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time

from detour_network import exact, socks
from dns_rule_support import proxy_client, udp_client
from udp_bind_port_network import certificate
from hy2_outbound_singbox import REVISION


def ready_line(process):
    if not select.select([process.stdout], [], [], 8)[0]:
        raise RuntimeError('host did not report state')
    line = process.stdout.readline().strip()
    if not line: raise RuntimeError(f'host exited {process.poll()}: {process.stderr.read()}')
    return line


def wait_proxy(port, process):
    deadline = time.monotonic() + 6
    while True:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2): return
        except OSError:
            if process.poll() is not None or time.monotonic() >= deadline: raise
            time.sleep(.02)


def closed(sock):
    sock.settimeout(4)
    try:
        if sock.recv(1): raise RuntimeError('unexpected data after host stop')
    except (ConnectionResetError, BrokenPipeError): pass


def run(fixture):
    if f'Revision: {REVISION}' not in subprocess.check_output(['sing-box', 'version'], text=True):
        raise RuntimeError('unexpected sing-box revision')
    with tempfile.TemporaryDirectory(prefix='hy2-active-restart-') as directory:
        root = Path(directory); certificate(root)
        process = subprocess.Popen([str(fixture), str(root / 'cert'), str(root / 'key'), 'active'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            old_port = None
            for index, expected in enumerate((1, 2, 1)):
                line = ready_line(process).split()
                if len(line) != 3 or line[0] != 'READY' or int(line[2]) != expected: raise RuntimeError(f'bad host state {line!r}')
                port = int(line[1])
                if old_port is not None and port != old_port: raise RuntimeError('host changed port')
                old_port = port
                outbound = {'type': 'hysteria2', 'server': '127.0.0.1', 'server_port': port, 'password': 'test-password',
                            'tls': {'enabled': True, 'server_name': 'localhost', 'certificate_path': str(root / 'cert'), 'alpn': ['h3']}}
                with socket.socket() as origin, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_origin, proxy_client(root, outbound) as front:
                    origin.bind(('127.0.0.1', 0)); origin.listen(1); origin.settimeout(8)
                    udp_origin.bind(('127.0.0.1', 0)); udp_origin.settimeout(5)
                    wait_proxy(front, process)
                    with udp_client(front) as (udp, relay), socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))[0] as client, origin.accept()[0] as peer:
                        udp_packet = b'\0\0\0\1' + socket.inet_aton('127.0.0.1') + udp_origin.getsockname()[1].to_bytes(2, 'big') + b'udp-active'
                        udp.sendto(udp_packet, relay)
                        payload, source = udp_origin.recvfrom(100)
                        if payload != b'udp-active': raise RuntimeError('UDP upload mismatch')
                        udp_origin.sendto(payload, source)
                        if udp.recvfrom(100)[0] != udp_packet: raise RuntimeError('UDP reply mismatch')
                        client.settimeout(5); peer.settimeout(5)
                        client.sendall(b'active');
                        if exact(peer, 6) != b'active': raise RuntimeError('upload mismatch')
                        peer.sendall(b'reply')
                        if exact(client, 5) != b'reply': raise RuntimeError('reply mismatch')
                        start = time.monotonic(); process.stdin.write('S'); process.stdin.flush()
                        if ready_line(process) != 'STOPPED': raise RuntimeError('host did not stop')
                        elapsed = time.monotonic() - start
                        if elapsed > 4: raise RuntimeError(f'host stop too slow: {elapsed:.2f}s')
                        closed(client); closed(peer)
                        udp_origin.settimeout(.35); udp.sendto(udp_packet, relay)
                        try:
                            udp_origin.recvfrom(100)
                            raise RuntimeError('UDP forwarded after host stopped')
                        except TimeoutError: pass
                        print(f'{expected} worker(s): active TCP and UDP stopped in {elapsed:.3f}s', flush=True)
                if index < 2: process.stdin.write('R'); process.stdin.flush()
            if process.wait(timeout=5): raise RuntimeError(f'host exit {process.returncode}: {process.stderr.read()}')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as check: check.bind(('127.0.0.1', old_port))
            print('same host restarted twice and released its UDP port')
        finally:
            if process.poll() is None: process.kill(); process.wait()
            process.stdin.close(); process.stdout.close(); process.stderr.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    args = parser.parse_args(); run(args.fixture.resolve(strict=True))
