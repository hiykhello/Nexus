#!/usr/bin/env python3
"""Production Hy2 over packet-capable outbounds against a fixed sing-box."""
import argparse
import base64
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from detour_network import reserve, socks, exact
from dns_rule_support import Echo, nexus_process, udp_client
from hy2_outbound_singbox import REVISION, active_stop, candidate_fallback, half_close, reject_password
from udp_bind_port_network import certificate


def udp_port(host):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def lower(kind, root, port):
    secret = root / 'password'
    tls = f'tls {{ server-name "localhost"; ca-file "{root / "cert"}"; verify #true; }}'
    prefix = f'outbound "lower" type="{kind}" {{ server host="127.0.0.1" port={port}; '
    if kind == 'shadowsocks':
        return prefix + f'method "2022-blake3-aes-128-gcm"; key-file "{root / "sskey"}"; udp-over-tcp "v2"; }}'
    if kind == 'vless':
        return prefix + f'authentication {{ uuid-file "{root / "uuid"}"; }}; {tls}; }}'
    if kind == 'snell':
        return prefix + f'version 4; psk-file "{root / "snell"}"; }}'
    if kind == 'hysteria2':
        return prefix + f'authentication {{ password-file "{secret}"; }}; {tls}; }}'
    return prefix + f'authentication {{ password-file "{secret}"; }}; {tls}; }}'


def run(binary, kinds, salamander=False, payload_limit=None, disable_pmtud=False):
    version = subprocess.check_output(['sing-box', 'version'], text=True)
    if f'Revision: {REVISION}' not in version:
        raise RuntimeError('unexpected sing-box revision')
    with tempfile.TemporaryDirectory(prefix='nexus-hy2-detour-') as directory:
        root = Path(directory)
        certificate(root)
        uuid = '00010203-0405-0607-0809-0a0b0c0d0e0f'
        ss = base64.b64encode(bytes(range(16))).decode()
        for name, value in [('password', 'test-password'), ('sskey', ss), ('uuid', uuid), ('snell', 'snell-test-secret'), ('obfs', 'salamander-secret')]:
            path = root / name; path.write_text(value + '\n'); path.chmod(0o600)
        wrong = root / 'wrong-password'; wrong.write_text('wrong-password\n'); wrong.chmod(0o600)
        for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            edge_port, hy2_lower = udp_port(host), udp_port('127.0.0.1')
            ports = {}
            for kind in kinds:
                if kind == 'hysteria2':
                    continue
                port = reserve()
                while port in ports.values():
                    port = reserve()
                ports[kind] = port
            ports['hysteria2'] = hy2_lower
            server_tls = {'enabled': True, 'certificate_path': str(root / 'cert'), 'key_path': str(root / 'key'), 'alpn': ['h3']}
            stream_tls = dict(server_tls); stream_tls.pop('alpn')
            inbounds = [{'type': 'hysteria2', 'tag': 'edge', 'listen': host, 'listen_port': edge_port,
                         'users': [{'password': 'test-password'}], 'tls': server_tls}]
            if salamander:
                inbounds[0]['obfs'] = {'type': 'salamander', 'password': 'salamander-secret'}
            for kind in kinds:
                inbound = {'type': kind, 'tag': kind, 'listen': '127.0.0.1', 'listen_port': ports[kind]}
                if kind == 'shadowsocks': inbound.update(method='2022-blake3-aes-128-gcm', password=ss)
                elif kind == 'snell': inbound.update(version=5, psk='snell-test-secret')
                elif kind == 'vless': inbound.update(users=[{'uuid': uuid}], tls=stream_tls)
                else: inbound.update(users=[{'password': 'test-password'}], tls=server_tls if kind == 'hysteria2' else stream_tls)
                inbounds.append(inbound)
            config = root / 'box.json'
            config.write_text(json.dumps({'log': {'level': 'debug'}, 'inbounds': inbounds,
                                          'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}))
            log = root / 'box.log'
            with log.open('wb') as output:
                box = subprocess.Popen(['sing-box', 'run', '-c', str(config)], stdout=output, stderr=subprocess.STDOUT)
                try:
                    time.sleep(.25)
                    if box.poll() is not None: raise RuntimeError(log.read_text())
                    for kind in kinds:
                        before = log.stat().st_size
                        front = reserve(); path = root / 'nexus.kdl'
                        quic_fields = []
                        if salamander: quic_fields.append(f'salamander-password-file "{root / "obfs"}";')
                        if payload_limit is not None: quic_fields.append(f'max-udp-payload-size {payload_limit};')
                        if disable_pmtud: quic_fields.append('disable-path-mtu-discovery #true;')
                        quic = 'quic { ' + ' '.join(quic_fields) + ' }' if quic_fields else ''
                        path.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{ server host="{host}" port={edge_port}; detour "lower";
 authentication {{ password-file "{root / 'password'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
 {quic}
}}
{lower(kind, root, ports[kind])}
routing {{ final "edge"; }}
''')
                        with Echo() as echo, nexus_process(str(binary), str(path)):
                            half_close(front)
                            with socks(front, 1, ('127.0.0.1', echo.port))[0] as client:
                                client.sendall(b'detour');
                                if exact(client, 6) != b'detour': raise RuntimeError('short TCP echo mismatch')
                            with udp_client(front) as (client, relay):
                                client.settimeout(10)
                                for target_family, target in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                                    address = bytes([1 if target_family == socket.AF_INET else 4]) + socket.inet_pton(target_family, target) + echo.port.to_bytes(2, 'big')
                                    for data in (b'', b'packet', bytes(range(256)) * 16):
                                        wire = b'\0\0\0' + address + data
                                        client.sendto(wire, relay)
                                        try:
                                            reply, _ = client.recvfrom(65535)
                                        except TimeoutError as error:
                                            raise RuntimeError(f'UDP timeout lower={kind} outer={host} target={target} size={len(data)}') from error
                                        if reply != wire: raise RuntimeError(f'UDP mismatch {kind} {len(data)}')
                        active_stop(binary, path, front)
                        text = log.read_text()[before:]
                        if f'inbound/{kind}[{kind}]' not in text:
                            raise RuntimeError(f'lower {kind} did not observe traffic: {text}')
                        print(f'Hy2 IPv{4 if family == socket.AF_INET else 6} via {kind}: TCP/FIN, dual-family UDP and active stop passed', flush=True)
                        if family == socket.AF_INET and kind in ('shadowsocks', 'hysteria2'):
                            original = path.read_text()
                            path.write_text(original.replace(f'password-file "{root / "password"}"', f'password-file "{wrong}"', 1))
                            reject_password(binary, path, front)
                            path.write_text(original)
                            print(f'Hy2 via {kind}: edge authentication failure rejected', flush=True)
                            if kind == 'hysteria2':
                                needle = f'password-file "{root / "password"}"'
                                head, separator, tail = original.rpartition(needle)
                                if not separator:
                                    raise RuntimeError('lower password field missing')
                                path.write_text(head + f'password-file "{wrong}"' + tail)
                                reject_password(binary, path, front)
                                path.write_text(original)
                                print('Hy2 via Hy2: lower authentication failure rejected', flush=True)
                            candidate_fallback(binary, root, path, front, edge_port, False, layered=True,
                                               obfs='salamander-secret' if salamander else None)
                            print(f'Hy2 via {kind}: failed candidate and bootstrap retry passed', flush=True)
                except BaseException:
                    print('peer diagnostics:', log.read_text(), flush=True)
                    raise
                finally:
                    if box.poll() is None: box.terminate()
                    box.wait(timeout=5)
                    if box.returncode: raise RuntimeError(f'sing-box exit {box.returncode}: {log.read_text()}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--lower', action='append', choices=('shadowsocks', 'trojan', 'vless', 'anytls', 'snell', 'hysteria2'))
    parser.add_argument('--salamander', action='store_true')
    parser.add_argument('--payload-limit', type=int)
    parser.add_argument('--disable-pmtud', action='store_true')
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.lower or ['shadowsocks', 'trojan', 'vless', 'anytls', 'snell', 'hysteria2'], args.salamander, args.payload_limit, args.disable_pmtud)
