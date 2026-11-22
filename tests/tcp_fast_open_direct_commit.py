#!/usr/bin/env python3
"""Verify a committed first write is not replayed to another DNS candidate.

Run inside an isolated network namespace with unshare -Urn.
"""
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading

from dns_rule_support import DnsPeer, connect, free_port, nexus_process, question

subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
with open('/proc/sys/net/ipv4/tcp_fastopen', 'w') as control:
    control.write('3')


class Candidates(DnsPeer):
    def reply(self, packet, transport):
        name, kind, end = question(packet)
        if name != 'candidates.test' or kind != 1:
            return super().reply(packet, transport)
        self.seen.append((name, kind, transport))
        records = b''.join(b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(ip)
                           for ip in ('127.0.0.2', '127.0.0.1'))
        return packet[:2] + struct.pack('!HHHHH', 0x8180, 1, 2, 0, 0) + packet[12:end] + records


with tempfile.TemporaryDirectory(prefix='nexus-tfo-commit-') as directory, Candidates() as dns:
    root = pathlib.Path(directory)
    fallback = socket.socket()
    fallback.bind(('127.0.0.1', 0))
    fallback.listen(1)
    fallback.settimeout(0.5)
    port = fallback.getsockname()[1]
    uncommitted = len(sys.argv) > 2 and sys.argv[2] == '--uncommitted'
    warm = socket.socket()
    warm.bind(('127.0.0.2', port))
    warm.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 8)
    warm.listen(1)
    warm.settimeout(3)
    errors = []

    def warm_server():
        try:
            with warm.accept()[0] as peer:
                peer.settimeout(3)
                if peer.recv(1) != b'x':
                    raise RuntimeError('cookie warm-up payload mismatch')
        except Exception as error:
            errors.append(repr(error))

    if not uncommitted:
        thread = threading.Thread(target=warm_server)
        thread.start()
        with socket.socket() as client:
            client.settimeout(3)
            try:
                client.sendto(b'x', socket.MSG_FASTOPEN, ('127.0.0.2', port))
            except BlockingIOError:
                client.sendall(b'x')
        thread.join(3)
        if thread.is_alive() or errors:
            raise RuntimeError(f'cookie warm-up failed: {errors}')
    warm.close()

    def fallback_server():
        try:
            with fallback.accept()[0] as peer:
                peer.settimeout(3)
                data = bytearray()
                while not data.endswith(b'\r\n\r\n'):
                    chunk = peer.recv(4096)
                    if not chunk or len(data) + len(chunk) > 4096:
                        raise RuntimeError('incomplete fallback request')
                    data += chunk
                if data.count(b'GET ') != 1:
                    raise RuntimeError('fallback request duplicated')
                peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
        except Exception as error:
            errors.append(repr(error))

    fallback_thread = threading.Thread(target=fallback_server) if uncommitted else None
    if fallback_thread:
        fallback_thread.start()

    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    raw.bind(('lo', 0))
    raw.settimeout(0.1)
    seen = []
    stopped = threading.Event()

    def capture():
        while not stopped.is_set():
            try:
                packet = raw.recv(65535)
            except TimeoutError:
                continue
            if len(packet) < 54 or packet[12:14] != b'\x08\x00' or packet[23] != 6:
                continue
            ihl = (packet[14] & 15) * 4
            start = 14 + ihl
            if len(packet) < start + 20:
                continue
            _, destination = struct.unpack_from('!HH', packet, start)
            flags = packet[start + 13]
            if destination != port or packet[30:34] != socket.inet_aton('127.0.0.2') or not flags & 2 or flags & 16:
                continue
            total = struct.unpack_from('!H', packet, 16)[0]
            tcp_header = (packet[start + 12] >> 4) * 4
            seen.append(total - ihl - tcp_header)

    capture_thread = threading.Thread(target=capture)
    capture_thread.start()
    try:
        front = free_port()
        config = root / 'client.kdl'
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{ tcp-fast-open #true; }}
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.port}; strategy "ipv4_only"; }}
routing {{ default-outbound "direct"; }}
''')
        with nexus_process(pathlib.Path(sys.argv[1]).resolve(), config):
            with connect(front) as client:
                client.settimeout(4)
                client.sendall(f'GET http://candidates.test:{port}/test HTTP/1.1\r\nHost: candidates.test:{port}\r\n\r\n'.encode())
                response = client.recv(4096)
                if not response.startswith(b'HTTP/1.1 200' if uncommitted else b'HTTP/1.1 502'):
                    raise RuntimeError(f'unexpected response: {response!r}')
            if fallback_thread:
                fallback_thread.join(3)
                if fallback_thread.is_alive() or errors:
                    raise RuntimeError(f'uncommitted fallback failed: {errors}')
            else:
                try:
                    fallback.accept()[0].close()
                except TimeoutError:
                    pass
                else:
                    raise RuntimeError('committed request replayed to second candidate')
    finally:
        stopped.set()
        capture_thread.join(2)
        raw.close()
        fallback.close()
    if capture_thread.is_alive() or not seen or (not uncommitted and not any(length > 0 for length in seen)) or (uncommitted and any(length > 0 for length in seen)):
        raise RuntimeError(f'no committed SYN data observed: {seen}')
    print(f'{"uncommitted first candidate retried" if uncommitted else "committed first candidate failed without replay"}; SYN payload lengths={seen}')
