#!/usr/bin/env python3
"""Exercise XUDP reply authorization and session renewal through SOCKS over TLS."""
import argparse
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from httpupgrade_cli_network import HOST, TARGET, transport_kdl
from httpupgrade_tls_network import RESPONSE, header as upgrade_header

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('nexus', type=pathlib.Path)
parser.add_argument('--ipv6', action='store_true')
parser.add_argument('--httpupgrade', action='store_true')
parser.add_argument('--workers', type=int, choices=(1, 2), default=1)
parser.add_argument('--error', choices=('length', 'oversized', 'kind', 'options', 'address', 'truncated-meta', 'truncated-payload'), default='length')
args = parser.parse_args()
nexus, ipv6 = args.nexus.resolve(), args.ipv6

ERRORS = {
    'length': b'\x00\x03',
    'oversized': b'\x02\x01',
    'kind': b'\x00\x04\x00\x02\x09\x00',
    'options': b'\x00\x04\x00\x02\x02\x04',
    'address': b'\x00\x08\x00\x02\x02\x00\x02\x00\x35\xff',
    'truncated-meta': b'\x00\x0c\x00\x02\x02\x01\x02\x00',
    'truncated-payload': b'\x00\x04\x00\x02\x02\x01\x00\x04x',
}

def exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('unexpected EOF')
        data += part
    return data

def frame(sock):
    length = int.from_bytes(exact(sock, 2), 'big')
    meta = exact(sock, length)
    data = exact(sock, int.from_bytes(exact(sock, 2), 'big')) if meta[3] & 1 else b''
    return meta, data

def response(session, kind, payload=b'', address=None):
    meta = session.to_bytes(2, 'big') + bytes([kind, bool(payload)])
    if address is not None:
        meta += b'\x02' + address
    return len(meta).to_bytes(2, 'big') + meta + (len(payload).to_bytes(2, 'big') + payload if payload else b'')

with tempfile.TemporaryDirectory(prefix='nexus-xudp-fault-') as directory:
    root = pathlib.Path(directory)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root/'key'), '-out', str(root/'cert'), '-subj', '/CN=cover.example', '-addext', 'subjectAltName=DNS:cover.example', '-days', '1'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root/'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n')
    (root/'uuid').chmod(0o600)
    with socket.socket() as listener, socket.socket() as reserve:
        listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(10)
        reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]; reserve.close()
        (root/'config').write_text(f'''schema-version 1
role "client"
workers {args.workers}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={listener.getsockname()[1]}; authentication {{ uuid-file "{root/'uuid'}"; }}; tls {{ server-name "cover.example"; ca-file "{root/'cert'}"; verify #true; }}
 {transport_kdl() if args.httpupgrade else ''}
}}
routing {{ default-outbound "edge"; }}
''')
        ended = threading.Event(); end_processed = threading.Event(); finished = threading.Event(); errors = []
        def server():
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/'cert', root/'key')
                if args.httpupgrade: context.set_alpn_protocols(['http/1.1'])
                raw, _ = listener.accept()
                with context.wrap_socket(raw, server_side=True) as sock:
                    sock.settimeout(10)
                    if args.httpupgrade:
                        if sock.selected_alpn_protocol() != 'http/1.1': raise RuntimeError('Upgrade did not negotiate h1')
                        wire = upgrade_header(sock)
                        if not wire.startswith(f'GET {TARGET} HTTP/1.1\r\nHost: {HOST}\r\n'.encode()): raise RuntimeError(f'wrong Upgrade before XUDP: {wire!r}')
                        sock.sendall(RESPONSE)
                    hello = exact(sock, 18)
                    if hello[:17] != b'\x00' + bytes(range(16)): raise RuntimeError('bad VLESS identity')
                    exact(sock, hello[17])
                    if exact(sock, 1) != b'\x03': raise RuntimeError('expected Mux')
                    sock.sendall(b'\x00\x00')
                    first, payload = frame(sock)
                    expected_address = b'\x02\x00\x35' + (b'\x03' + socket.inet_pton(socket.AF_INET6, '::1') if ipv6 else b'\x01\x7f\x00\x00\x01')
                    if first != b'\x00\x01\x01\x01' + expected_address or payload != b'first': raise RuntimeError(f'bad first open {first!r} {payload!r}')
                    # Forge an explicit source, then send the authorized implicit source.
                    forged = b'\x00\x35' + (b'\x03' + socket.inet_pton(socket.AF_INET6, '::2') if ipv6 else b'\x01\x7f\x00\x00\x02')
                    sock.sendall(response(1, 2, b'forged', forged) + response(1, 2, b'good'))
                    if not ended.wait(10): raise RuntimeError('end gate timed out')
                    sock.sendall(response(1, 3) + response(99, 2, b'probe'))
                    acknowledgement, payload = frame(sock)
                    if acknowledgement[:4] != b'\x00\x63\x03\x00' or payload: raise RuntimeError('end barrier failed')
                    end_processed.set()
                    second, payload = frame(sock)
                    if second[:4] != b'\x00\x02\x01\x01' or payload != b'second': raise RuntimeError(f'expected new open {second!r} {payload!r}')
                    sock.sendall(response(2, 2, b'good2'))
                    if not finished.wait(10): raise RuntimeError('finish gate timed out')
                    sock.sendall(ERRORS[args.error])
                    if args.error.startswith('truncated-'):
                        # An incomplete XUDP message plus unauthenticated TCP
                        # EOF must fail and close the SOCKS control owner.
                        sock.shutdown(socket.SHUT_WR)
                    if sock.recv(1): raise RuntimeError('tunnel remained open after malformed frame')
            except Exception as exc:
                errors.append(exc); ended.set(); end_processed.set(); finished.set()
        thread = threading.Thread(target=server, daemon=True); thread.start()
        proxy = subprocess.Popen([nexus, 'run', '--config', root/'config'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while True:
                if proxy.poll() is not None: raise RuntimeError(f'proxy exited: {proxy.stderr.read()!r}')
                try: control = socket.create_connection(('127.0.0.1', port), timeout=1); break
                except ConnectionRefusedError:
                    if time.monotonic() > deadline: raise
                    time.sleep(.05)
            with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                control.settimeout(10); udp.settimeout(10); udp.bind(('127.0.0.1', 0))
                control.sendall(b'\x05\x01\x00'); assert exact(control, 2) == b'\x05\x00'
                control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00'); reply = exact(control, 10)
                if reply[:4] != b'\x05\x00\x00\x01': raise RuntimeError(f'association {reply!r}')
                relay = (socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:10], 'big'))
                header = b'\x00\x00\x00' + (b'\x04' + socket.inet_pton(socket.AF_INET6, '::1') if ipv6 else b'\x01\x7f\x00\x00\x01') + b'\x00\x35'
                udp.sendto(header+b'first', relay)
                if udp.recvfrom(65535)[0] != header+b'good': raise RuntimeError('forged or incorrect first response')
                udp.settimeout(.2)
                try: raise RuntimeError(f'extra response {udp.recvfrom(65535)!r}')
                except socket.timeout: pass
                ended.set()
                if not end_processed.wait(10) or errors: raise RuntimeError(f'end barrier: {errors}')
                udp.settimeout(10); udp.sendto(header+b'second', relay)
                if udp.recvfrom(65535)[0] != header+b'good2': raise RuntimeError('incorrect renewed session response')
                finished.set()
                try: closed = control.recv(1)
                except ConnectionResetError: closed = b''
                if closed: raise RuntimeError('SOCKS control survived malformed frame')
            thread.join(10)
            if thread.is_alive() or errors: raise RuntimeError(f'fixture failure: {errors}')
        finally:
            ended.set(); finished.set()
            if proxy.poll() is None: proxy.terminate()
            _, stderr = proxy.communicate(timeout=5)
            if proxy.returncode: raise RuntimeError(f'proxy exit {proxy.returncode}: {stderr!r}')
print(f'XUDP SOCKS ordinary ID1 rejects forged replies, renews ID2 after end, and closes on {args.error}: '
      f'transport={"httpupgrade" if args.httpupgrade else "TLS"}, workers={args.workers}, IPv6={ipv6}')
