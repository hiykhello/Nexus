#!/usr/bin/env python3
"""Single-worker production Hy2 listener resolves a remote domain via DNS."""
import argparse
from pathlib import Path
import socket
import subprocess
import tempfile
import threading

from detour_network import Dns
from dns_rule_support import nexus_process
from hy2_outbound_detour import udp_port
from udp_bind_port_network import certificate


def run(binary, peer, family):
    host = "::1" if family == 6 else "127.0.0.1"
    with tempfile.TemporaryDirectory(prefix='hy2-single-worker-dns-') as directory:
        root = Path(directory); certificate(root)
        cert = root / 'cert.der'
        subprocess.run(['openssl', 'x509', '-in', str(root / 'cert'), '-outform', 'DER', '-out', str(cert)], check=True, capture_output=True)
        for name, value in (('password', 'test-password'), ('obfs', 'salamander-secret')):
            path = root / name; path.write_text(value + '\n'); path.chmod(0o600)
        dns = Dns()
        try:
            port = udp_port(host); config = root / 'server.kdl'
            config.write_text(f'''schema-version 1
role "server"
workers 1
dns {{ server "test" type="udp" host="127.0.0.1" port={dns.port}; strategy "ipv4_only"; }}
inbound "edge" type="hysteria2" {{ listen host="{host}" port={port};
 authentication {{ user "test" password-file="{root / 'password'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
 quic {{ salamander-password-file "{root / 'obfs'}"; }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
            payload = bytes(range(256)) * 512; errors = []
            with socket.socket() as origin:
                origin.bind(('127.0.0.1', 0)); origin.listen(1); origin.settimeout(10)
                def serve():
                    try:
                        with origin.accept()[0] as conn:
                            conn.settimeout(10); data = bytearray()
                            while part := conn.recv(16384): data.extend(part)
                            if data != payload: raise RuntimeError('wrong upload')
                            conn.sendall(data); conn.shutdown(socket.SHUT_WR)
                    except BaseException as error: errors.append(repr(error))
                thread = threading.Thread(target=serve); thread.start()
                try:
                    with nexus_process(str(binary), str(config)):
                        result = subprocess.run([str(peer), str(family), str(port), str(cert),
                                                 f'target.test:{origin.getsockname()[1]}'], capture_output=True, text=True, timeout=15)
                        if result.returncode: raise RuntimeError(f'peer failed: {result.stdout} {result.stderr}')
                        if 'target.test' not in dns.names: raise RuntimeError('Hy2 domain did not reach DNS')
                finally: thread.join(12)
                if thread.is_alive() or errors: raise RuntimeError(f'origin failed: {errors!r}')
            print(f'single-worker IPv{family} Hy2 remote domain used configured DNS; TCP/FIN passed')
        finally: dns.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path); parser.add_argument('peer', type=Path)
    args = parser.parse_args()
    for family in (4, 6): run(args.binary.resolve(strict=True), args.peer.resolve(strict=True), family)
