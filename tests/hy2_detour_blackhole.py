#!/usr/bin/env python3
"""Bound the entire Hy2-over-SS handshake and stop a live lower stream."""
import argparse
import base64
from pathlib import Path
import socket
import threading
import time
import tempfile

from detour_network import exact, reserve
from dns_rule_support import nexus_process
from udp_bind_port_network import certificate


def run(binary, stop):
    with tempfile.TemporaryDirectory(prefix='nexus-hy2-detour-deadline-') as directory:
        root = Path(directory); certificate(root)
        for name, value in [('password', 'test-password'), ('sskey', base64.b64encode(bytes(range(16))).decode())]:
            path = root / name; path.write_text(value + '\n'); path.chmod(0o600)
        with socket.socket() as lower:
            lower.bind(('127.0.0.1', 0)); lower.listen(1); lower.settimeout(5)
            front = reserve(); config = root / 'nexus.kdl'
            timeout = 5000 if stop else 400
            config.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "lower" type="shadowsocks" {{ server host="127.0.0.1" port={lower.getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root / 'sskey'}"; udp-over-tcp "v2"; }}
outbound "edge" type="hysteria2" {{ server host="127.0.0.1" port=443; detour "lower"; connect-timeout-ms {timeout};
 authentication {{ password-file "{root / 'password'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
routing {{ default-outbound "edge"; }}
''')
            with nexus_process(str(binary), str(config)):
                client = socket.create_connection(('127.0.0.1', front), timeout=3);client.settimeout(3)
                client.sendall(b'\x05\x01\x00')
                if exact(client, 2) != b'\x05\x00': raise RuntimeError('SOCKS greeting failed')
                started = time.monotonic()
                client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50')
                peer, _ = lower.accept();peer.settimeout(3)
                if not peer.recv(4096): raise RuntimeError('lower did not receive protocol bytes')
                if not stop:
                    reply = exact(client, 10); elapsed = time.monotonic() - started
                    if reply[1] != 6 or not .2 <= elapsed < 1.7:
                        raise RuntimeError(f'wrong absolute deadline: {reply!r} {elapsed:.3f}s')
            with client, peer:
                for stream in (client, peer):
                    stream.settimeout(3)
                    try:
                        while stream.recv(4096): pass
                    except ConnectionResetError:
                        pass
    print('pending lower stop passed' if stop else 'shared 400ms deadline passed', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    run(binary, False); run(binary, True)
