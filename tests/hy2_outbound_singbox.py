#!/usr/bin/env python3
"""Exercise the production Hysteria 2 outbound against a fixed sing-box peer."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from detour_network import Dns, reserve, socks, exact
from dns_rule_support import DnsPeer, Echo, nexus_process, udp_client
from udp_bind_port_network import certificate

REVISION = '824dbcfb4dd0a95921840b1737b950cde590241e'


def half_close(front):
    payload = bytes(range(256)) * 512
    errors = []
    with socket.socket() as origin:
        origin.bind(('127.0.0.1', 0))
        origin.listen(1)
        origin.settimeout(10)
        def serve():
            try:
                with origin.accept()[0] as peer:
                    peer.settimeout(10)
                    received = bytearray()
                    while part := peer.recv(16384):
                        received.extend(part)
                    if received != payload:
                        raise RuntimeError('half-close upload mismatch')
                    peer.sendall(received)
                    peer.shutdown(socket.SHUT_WR)
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))[0] as client:
                client.settimeout(10)
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                if exact(client, len(payload)) != payload or client.recv(1):
                    raise RuntimeError('half-close download mismatch')
        finally:
            thread.join(12)
        if thread.is_alive() or errors:
            raise RuntimeError(f'origin did not finish: {errors!r}')


def active_stop(binary, config, front):
    with socket.socket() as origin:
        origin.bind(('127.0.0.1', 0))
        origin.listen(1)
        origin.settimeout(10)
        with nexus_process(str(binary), str(config)):
            client, _ = socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))
            peer, _ = origin.accept()
        with client, peer:
            for stream in (client, peer):
                stream.settimeout(5)
                try:
                    if stream.recv(1):
                        raise RuntimeError('active stream survived shutdown')
                except ConnectionResetError:
                    pass


def reject_password(binary, config, front):
    with socket.socket() as origin:
        origin.bind(('127.0.0.1', 0))
        origin.listen(1)
        origin.settimeout(.5)
        with nexus_process(str(binary), str(config)):
            with socket.create_connection(('127.0.0.1', front), timeout=6) as client:
                client.settimeout(6)
                client.sendall(b'\x05\x01\x00')
                if exact(client, 2) != b'\x05\x00':
                    raise RuntimeError('SOCKS greeting failed')
                client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + origin.getsockname()[1].to_bytes(2, 'big'))
                reply = exact(client, 10)
                if reply[1] == 0:
                    raise RuntimeError('wrong password accepted')
            try:
                peer, _ = origin.accept()
            except TimeoutError:
                pass
            else:
                peer.close()
                raise RuntimeError('wrong password reached origin')


def blackhole(binary, config, front, family, host, original_port):
    with socket.socket(family, socket.SOCK_DGRAM) as silent:
        silent.bind((host, 0))
        silent.settimeout(3)
        config.write_text(config.read_text().replace(f'port={original_port};',
            f'port={silent.getsockname()[1]}; connect-timeout-ms 300;'))
        with nexus_process(str(binary), str(config)):
            with socket.create_connection(('127.0.0.1', front), timeout=5) as client:
                client.settimeout(3)
                client.sendall(b'\x05\x01\x00')
                if exact(client, 2) != b'\x05\x00':
                    raise RuntimeError('SOCKS greeting failed')
                started = time.monotonic()
                client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50')
                silent.recvfrom(4096)
                reply = exact(client, 10)
                elapsed = time.monotonic() - started
                if reply[1] == 0 or not .15 <= elapsed < 2:
                    raise RuntimeError(f'blackhole deadline: reply={reply!r}, elapsed={elapsed:.3f}')

        # Discard earlier retransmissions before observing the next handshake.
        silent.setblocking(False)
        try:
            while True:
                silent.recvfrom(4096)
        except BlockingIOError:
            pass
        silent.settimeout(3)
        # Stop while an independent handshake is actually waiting on the silent peer.
        config.write_text(config.read_text().replace('connect-timeout-ms 300;', 'connect-timeout-ms 5000;'))
        with nexus_process(str(binary), str(config)):
            client = socket.create_connection(('127.0.0.1', front), timeout=5)
            client.settimeout(3)
            client.sendall(b'\x05\x01\x00')
            if exact(client, 2) != b'\x05\x00':
                raise RuntimeError('SOCKS greeting failed')
            client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50')
            silent.recvfrom(4096)
        with client:
            try:
                data = client.recv(10)
                if data and (len(data) < 2 or data[1] == 0):
                    raise RuntimeError('pending handshake survived shutdown')
            except ConnectionResetError:
                pass


def candidate_fallback(binary, root, config, front, port, detour, layered=False, obfs=None):
    # First candidate reaches a real peer but fails TLS verification; second
    # uses the good certificate. Physical attempts must reuse the source port.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        source_port = reservation.getsockname()[1]
    bad_cert, bad_key = root / 'bad-cert', root / 'bad-key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=wrong', '-addext', 'subjectAltName=DNS:wrong',
                    '-keyout', str(bad_key), '-out', str(bad_cert)], check=True, capture_output=True)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        bad_port = reservation.getsockname()[1]
    bad_config = root / 'bad-box.json'
    bad_inbound = {'type': 'hysteria2', 'listen': '127.0.0.1', 'listen_port': bad_port,
                      'users': [{'name': 'test', 'password': 'test-password'}],
                      'tls': {'enabled': True, 'certificate_path': str(bad_cert),
                              'key_path': str(bad_key), 'alpn': ['h3']}}
    if obfs:
        bad_inbound['obfs'] = {'type': 'salamander', 'password': obfs}
    bad_config.write_text(json.dumps({'log': {'level': 'debug'},
        'inbounds': [bad_inbound],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}))
    bad = subprocess.Popen(['sing-box', 'run', '-c', bad_config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    dns = Dns(answers={'hy2.test': ('127.0.0.2', '127.0.0.1')})
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind(('127.0.0.2', port)); relay.settimeout(.1)
    seen = []
    stopped = threading.Event()
    def forward():
        client = None
        while not stopped.is_set():
            try:
                packet, source = relay.recvfrom(65535)
            except TimeoutError:
                continue
            if source == ('127.0.0.1', bad_port):
                if client:
                    relay.sendto(packet, client)
            else:
                client = source
                seen.append(source)
                relay.sendto(packet, ('127.0.0.1', bad_port))
    thread = threading.Thread(target=forward)
    thread.start()
    try:
        time.sleep(.2)
        if bad.poll() is not None:
            raise RuntimeError(bad.communicate())
        text = config.read_text().replace('server host="127.0.0.1"', 'server host="hy2.test"', 1)
        text = text.replace('role "client"',
            f'role "client"\ndns {{ server "boot" type="udp" host="127.0.0.1" port={dns.port}; strategy "ipv4_only"; }}')
        text = text.replace('outbound "edge" type="hysteria2" {',
            'outbound "edge" type="hysteria2" { bootstrap-resolver "boot";')
        if not layered and detour:
            text = text.replace('outbound "direct" type="direct"',
                f'outbound "direct" type="direct" {{ udp-bind-port {source_port}; }}')
        elif not layered:
            text = text.replace('bootstrap-resolver "boot";',
                f'bootstrap-resolver "boot"; udp-bind-port {source_port};')
        config.write_text(text)
        with Echo() as echo, nexus_process(str(binary), str(config)):
            with socks(front, 1, ('127.0.0.1', echo.port))[0] as client:
                client.sendall(b'candidate')
                if exact(client, 9) != b'candidate':
                    raise RuntimeError('candidate fallback response mismatch')
        if 'hy2.test' not in dns.names:
            raise RuntimeError('candidate bootstrap was not queried')
        if not seen or (not layered and any(source[1] != source_port for source in seen)):
            raise RuntimeError(f'first candidate or bound source port not observed: {seen!r}')
    finally:
        stopped.set();thread.join(2);relay.close()
        if thread.is_alive():
            raise RuntimeError('candidate relay did not stop')
        dns.close()
        if bad.poll() is None:
            bad.terminate()
        _, diagnostics = bad.communicate(timeout=5)
        if bad.returncode:
            raise RuntimeError(f'bad peer exit {bad.returncode}: {diagnostics!r}')


def run(binary):
    version = subprocess.check_output(['sing-box', 'version'], text=True)
    if f'Revision: {REVISION}' not in version:
        raise RuntimeError('unexpected sing-box revision')
    with tempfile.TemporaryDirectory(prefix='nexus-hy2-outbound-') as directory:
        root = Path(directory)
        certificate(root)
        password = root / 'password'
        password.write_text('test-password\n')
        password.chmod(0o600)
        for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            with socket.socket(family, socket.SOCK_DGRAM) as reservation:
                reservation.bind((host, 0))
                port = reservation.getsockname()[1]
            config = root / 'sing-box.json'
            config.write_text(json.dumps({
                'log': {'level': 'debug'},
                'inbounds': [{'type': 'hysteria2', 'listen': host, 'listen_port': port,
                              'users': [{'name': 'test', 'password': 'test-password'}],
                              'tls': {'enabled': True, 'certificate_path': str(root / 'cert'),
                                      'key_path': str(root / 'key'), 'alpn': ['h3']}}],
                'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}))
            box = subprocess.Popen(['sing-box', 'run', '-c', config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                time.sleep(.2)
                if box.poll() is not None:
                    raise RuntimeError(box.communicate())
                for detour in (False, True):
                    front = reserve()
                    nexus = root / 'nexus.kdl'
                    nexus.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{ server host="{host}" port={port};
 authentication {{ password-file "{password}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
 {'detour "direct";' if detour else ''}
}}
routing {{ final "edge"; }}
''')
                    with Echo() as echo, nexus_process(str(binary), str(nexus)):
                        half_close(front)
                        with socks(front, 1, ('127.0.0.1', echo.port))[0] as client:
                            client.sendall(b'hy2-tcp')
                            if exact(client, 7) != b'hy2-tcp':
                                raise RuntimeError('TCP echo mismatch')
                        with udp_client(front) as (client, relay):
                            client.settimeout(8)
                            for target_family, target in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                                address = bytes([1 if target_family == socket.AF_INET else 4]) + socket.inet_pton(target_family, target) + echo.port.to_bytes(2, 'big')
                                for payload in (b'', b'hy2-udp', bytes(range(256)) * 16):
                                    request = b'\0\0\0' + address + payload
                                    client.sendto(request, relay)
                                    response, _ = client.recvfrom(65535)
                                    if response != request:
                                        raise RuntimeError(f'UDP echo mismatch: {len(payload)} bytes')
                    active_stop(binary, nexus, front)
                    password.write_text('wrong-password\n')
                    try:
                        reject_password(binary, nexus, front)
                    finally:
                        password.write_text('test-password\n')
                    base_config = nexus.read_text()
                    with DnsPeer() as dns:
                        text = base_config.replace(f'server host="{host}"', 'server host="hy2.test"')
                        text = text.replace('outbound "edge" type="hysteria2" {',
                            'outbound "edge" type="hysteria2" { bootstrap-resolver "boot";')
                        strategy = 'ipv4_only' if family == socket.AF_INET else 'ipv6_only'
                        text = text.replace('role "client"',
                            f'role "client"\ndns {{ server "boot" type="udp" host="127.0.0.1" port={dns.port}; strategy "{strategy}"; }}')
                        nexus.write_text(text)
                        with Echo() as echo, nexus_process(str(binary), str(nexus)):
                            with socks(front, 1, ('127.0.0.1', echo.port))[0] as client:
                                client.sendall(b'bootstrap')
                                if exact(client, 9) != b'bootstrap':
                                    raise RuntimeError('bootstrap TCP echo mismatch')
                        kind = 1 if family == socket.AF_INET else 28
                        if not dns.count('hy2.test', kind):
                            raise RuntimeError('configured bootstrap resolver was not queried')
                    nexus.write_text(base_config)
                    if family == socket.AF_INET:
                        candidate_fallback(binary, root, nexus, front, port, detour)
                        nexus.write_text(base_config)
                    blackhole(binary, nexus, front, family, host, port)
                    checks = 'bootstrap/candidate retry' if family == socket.AF_INET else 'bootstrap'
                    print(f'outer IPv{4 if family == socket.AF_INET else 6}, direct detour={detour}: TCP/FIN, UDP, {checks}, authentication, deadline, active and pending stop passed', flush=True)
            except BaseException:
                box.terminate()
                _, error = box.communicate(timeout=5)
                print('sing-box diagnostics:', error.decode(errors='replace'), flush=True)
                raise
            finally:
                if box.poll() is None:
                    box.terminate()
                _, error = box.communicate(timeout=5)
                if box.returncode:
                    raise RuntimeError(f'sing-box exit {box.returncode}: {error!r}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    run(parser.parse_args().binary.resolve(strict=True))
