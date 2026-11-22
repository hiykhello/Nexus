#!/usr/bin/env python3
"""Exercise a production Hy2 outbound while its real shared UDP budget is held."""
import argparse
import base64
import json
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time

from detour_network import reserve
from dns_rule_support import Echo, udp_client
from hy2_outbound_detour import udp_port
from hy2_outbound_singbox import REVISION
from udp_bind_port_network import certificate


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise RuntimeError('timed out waiting for origin packet')
        time.sleep(.01)


def run(binary, lower):
    if f'Revision: {REVISION}' not in subprocess.check_output(['sing-box', 'version'], text=True):
        raise RuntimeError('unexpected sing-box revision')
    with tempfile.TemporaryDirectory(prefix='hy2-production-budget-') as directory:
        root = Path(directory)
        certificate(root)
        password = root / 'password'
        password.write_text('test-password\n')
        password.chmod(0o600)
        peer_port, front = udp_port('127.0.0.1'), reserve()
        config = root / 'box.json'
        inbounds = [{
            'type': 'hysteria2', 'listen': '127.0.0.1', 'listen_port': peer_port,
            'users': [{'password': 'test-password'}], 'tls': {'enabled': True,
            'certificate_path': str(root / 'cert'), 'key_path': str(root / 'key'), 'alpn': ['h3']}}]
        detour = ''
        lower_config = ''
        if lower:
            key = base64.b64encode(bytes(range(16))).decode()
            key_file = root / 'sskey'; key_file.write_text(key + '\n'); key_file.chmod(0o600)
            lower_port = reserve()
            inbounds.append({'type': 'shadowsocks', 'tag': 'lower', 'listen': '127.0.0.1', 'listen_port': lower_port,
                             'method': '2022-blake3-aes-128-gcm', 'password': key})
            detour = 'detour "lower";'
            lower_config = f'''outbound "lower" type="shadowsocks" {{ server host="127.0.0.1" port={lower_port};
 method "2022-blake3-aes-128-gcm"; key-file "{key_file}"; udp-over-tcp "v2"; }}'''
        config.write_text(json.dumps({'log': {'level': 'info'}, 'inbounds': inbounds,
            'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}))
        path = root / 'nexus.kdl'
        path.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{ server host="127.0.0.1" port={peer_port}; {detour}
 authentication {{ password-file "{password}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
{lower_config}
routing {{ default-outbound "edge"; }}
''')
        peer_log = (root / 'box.log').open('w+b')
        box = subprocess.Popen(['sing-box', 'run', '-c', str(config)], stdout=peer_log, stderr=subprocess.STDOUT)
        process = None
        try:
            time.sleep(.25)
            if box.poll() is not None:
                raise RuntimeError(f'sing-box startup failed: {(root / "box.log").read_text()}')
            process = subprocess.Popen(['stdbuf', '-oL', str(binary), '--config', str(path)],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if not select.select([process.stdout], [], [], 8)[0] or b'listening' not in process.stdout.readline():
                raise RuntimeError('Nexus listener did not start')
            with Echo() as echo, udp_client(front) as (client, relay):
                header = b'\0\0\0\1' + socket.inet_aton('127.0.0.1') + echo.port.to_bytes(2, 'big')
                def exchange(data, timeout):
                    client.sendto(header + data, relay)
                    wait_for(lambda: data in echo.received)
                    client.settimeout(timeout)
                    try:
                        return client.recvfrom(65535)[0]
                    except TimeoutError:
                        return None
                small = b'budget-preflight'
                if exchange(small, 5) != header + small:
                    raise RuntimeError('unfragmented preflight failed with budget held')
                first = bytes(range(256)) * 16
                if exchange(first, .8) is not None:
                    raise RuntimeError('fragmented reply survived exhausted budget')
                process.stdin.write(b'release\n'); process.stdin.flush()
                if not select.select([process.stderr], [], [], 5)[0]:
                    raise RuntimeError('budget release not acknowledged')
                acknowledgment = process.stderr.readline()
                if acknowledgment != b'budget released used=0\n':
                    raise RuntimeError(f'unexpected budget state: {acknowledgment!r}')
                second = bytes(reversed(range(256))) * 16
                if exchange(second, 5) != header + second:
                    raise RuntimeError('fragmented reply did not recover on same association')
                if lower and 'inbound/shadowsocks[lower]: inbound connection from' not in (root / 'box.log').read_text():
                    raise RuntimeError('SS lower inbound did not observe the connection')
                print(f'production Hy2 UDP via {"SS UoT" if lower else "physical UDP"}: exhausted reply dropped; same association recovered after budget release', flush=True)
        finally:
            if process:
                if process.stdin and not process.stdin.closed:
                    try:
                        process.stdin.write(b'release\n'); process.stdin.flush()
                    except BrokenPipeError:
                        pass
                if process.poll() is None:
                    process.terminate()
                output, error = process.communicate(timeout=8)
                if process.returncode:
                    raise RuntimeError(f'Nexus exit {process.returncode}: stdout={output!r} stderr={error!r}')
            if box.poll() is None:
                box.terminate()
            box.wait(timeout=5)
            peer_log.close()
            if box.returncode:
                raise RuntimeError(f'sing-box exit {box.returncode}: {(root / "box.log").read_text()}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--lower-ss', action='store_true')
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.lower_ss)
