#!/usr/bin/env python3
"""Production Hy2 Salamander client/server against pinned sing-box."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from detour_network import exact, reserve, socks
from dns_rule_support import Echo, nexus_process, proxy_client, udp_client
from hy2_outbound_detour import udp_port
from hy2_outbound_singbox import REVISION, half_close, reject_password
from udp_bind_port_network import certificate


def udp_echo(front, origin, hold=0):
    with udp_client(front) as (client, relay):
        client.settimeout(8)
        for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            address = bytes([1 if family == socket.AF_INET else 4]) + socket.inet_pton(family, host) + origin.to_bytes(2, 'big')
            for payload in (b'salamander', bytes(range(256)) * 16):
                packet = b'\0\0\0' + address + payload
                client.sendto(packet, relay)
                if client.recvfrom(65535)[0] != packet:
                    raise RuntimeError(f'UDP mismatch for {host}, size {len(payload)}')
        if hold:
            time.sleep(hold)
            packet = b'\0\0\0\1' + socket.inet_aton('127.0.0.1') + origin.to_bytes(2, 'big') + b'after-probe'
            client.sendto(packet, relay)
            if client.recvfrom(65535)[0] != packet: raise RuntimeError('UDP failed after MTU probing')


def independent_half_close(peer, family, port, cert):
    errors = []
    with socket.socket() as origin:
        origin.bind(('127.0.0.1', 0)); origin.listen(1); origin.settimeout(10)
        def serve():
            try:
                with origin.accept()[0] as conn:
                    conn.settimeout(10); data = bytearray()
                    while part := conn.recv(16384): data.extend(part)
                    if data != bytes(range(256)) * 512: raise RuntimeError('origin received wrong payload')
                    conn.sendall(data); conn.shutdown(socket.SHUT_WR)
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=serve); thread.start()
        try:
            result = subprocess.run([str(peer), '6' if family == socket.AF_INET6 else '4', str(port), str(cert),
                                     f'127.0.0.1:{origin.getsockname()[1]}'], capture_output=True, text=True, timeout=12)
        finally:
            thread.join(12)
        if result.returncode: raise RuntimeError(f'peer exit {result.returncode}: {result.stdout} {result.stderr}; origin errors={errors!r}')
        if thread.is_alive() or errors: raise RuntimeError(f'origin failed: {errors!r}')


def run(binary, peer, forbid_fragment, peer_receive_rate):
    if f'Revision: {REVISION}' not in subprocess.check_output(['sing-box', 'version'], text=True):
        raise RuntimeError('unexpected sing-box revision')
    with tempfile.TemporaryDirectory(prefix='nexus-hy2-salamander-') as directory:
        root = Path(directory); certificate(root)
        der = root / 'cert.der'
        subprocess.run(['openssl', 'x509', '-in', str(root / 'cert'), '-outform', 'DER', '-out', str(der)], check=True, capture_output=True)
        for name, value in (('password', 'test-password'), ('obfs', 'salamander-secret'), ('wrong-obfs', 'different-salamander-secret')):
            path = root / name; path.write_text(value + '\n'); path.chmod(0o600)
        for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            port = udp_port(host); front = reserve()
            path = root / 'nexus.kdl'
            base = f'''schema-version 1
role "client"
workers 2
outbound "direct" type="direct"
'''
            tls = {'enabled': True, 'certificate_path': str(root / 'cert'), 'key_path': str(root / 'key'), 'alpn': ['h3']}
            obfs = {'type': 'salamander', 'password': 'salamander-secret'}
            config = root / 'box-server.json'
            config.write_text(json.dumps({'log': {'level': 'warn'}, 'inbounds': [{'type': 'hysteria2',
                'listen': host, 'listen_port': port, 'users': [{'password': 'test-password'}], 'tls': tls, 'obfs': obfs}],
                'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}))
            box = subprocess.Popen(['sing-box', 'run', '-c', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                time.sleep(.25)
                if box.poll() is not None: raise RuntimeError(f'sing-box failed: {box.communicate()}')
                fragment = 'udp-fragment #false;' if forbid_fragment else ''
                path.write_text(base + f'''inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "edge" type="hysteria2" {{ server host="{host}" port={port}; {fragment}
 authentication {{ password-file "{root / 'password'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
 quic {{ salamander-password-file "{root / 'obfs'}"; }}
}}
routing {{ final "edge"; }}
''')
                with Echo() as echo, nexus_process(str(binary), str(path)):
                    half_close(front); udp_echo(front, echo.port)
                original = path.read_text()
                path.write_text(original.replace(f'salamander-password-file "{root / "obfs"}"',
                                                 f'salamander-password-file "{root / "wrong-obfs"}"')
                                .replace(f'port={port};', f'port={port}; connect-timeout-ms 400;', 1))
                reject_password(binary, path, front)
                path.write_text(original)
                print(f'Nexus Salamander outbound IPv{4 if family == socket.AF_INET else 6}: TCP/FIN and dual-family UDP passed', flush=True)
            finally:
                if box.poll() is None: box.terminate()
                _, error = box.communicate(timeout=5)
                if box.returncode: raise RuntimeError(f'sing-box server exit {box.returncode}: {error!r}')
            path.write_text(base + f'''inbound "edge" type="hysteria2" {{ listen host="{host}" port={port};
 authentication {{ user "test" password-file="{root / 'password'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
 quic {{ salamander-password-file "{root / 'obfs'}"; }}
}}
routing {{ final "direct"; }}
''')
            outbound = {'type': 'hysteria2', 'server': host, 'server_port': port, 'password': 'test-password',
                        'tls': {'enabled': True, 'server_name': 'localhost', 'certificate_path': str(root / 'cert'), 'alpn': ['h3']}, 'obfs': obfs}
            if peer_receive_rate: outbound['down_mbps'] = 10
            with Echo() as echo, nexus_process(str(binary), str(path)):
                independent_half_close(peer, family, port, der)
                with proxy_client(root, outbound) as front:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            with socket.create_connection(('127.0.0.1', front), timeout=.2): pass
                            break
                        except ConnectionRefusedError:
                            if time.monotonic() >= deadline: raise
                            time.sleep(.02)
                    with socks(front, 1, ('127.0.0.1', echo.port))[0] as client:
                        client.sendall(b'salamander-tcp')
                        if exact(client, 14) != b'salamander-tcp': raise RuntimeError('TCP echo mismatch')
                    udp_echo(front, echo.port)
            print(f'Nexus Salamander inbound IPv{4 if family == socket.AF_INET else 6}: TCP/FIN and dual-family UDP passed, peer receive rate={peer_receive_rate}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('peer', type=Path)
    parser.add_argument('--forbid-fragment', action='store_true')
    parser.add_argument('--peer-receive-rate', action='store_true', help='have the fixed client advertise a nonzero receive rate')
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.peer.resolve(strict=True), args.forbid_fragment, args.peer_receive_rate)
