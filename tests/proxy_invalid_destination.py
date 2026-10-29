#!/usr/bin/env python3
"""Reject unspecified TCP targets while retaining valid DNS fallback."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time


def exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('unexpected EOF')
        data += part
    return data


def scenario(binary, workers):
    with tempfile.TemporaryDirectory() as tmp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns, socket.socket() as target:
        dns.bind(('127.0.0.1', 0)); dns.settimeout(.1)
        target.bind(('127.0.0.1', 0)); target.listen(8); target.settimeout(.2)
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
        config = pathlib.Path(tmp) / 'config.kdl'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
dns {{ server "local" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; disable-cache #true; }}
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        stop = threading.Event()
        queries = []
        def answer():
            while not stop.is_set():
                try: query, peer = dns.recvfrom(2048)
                except TimeoutError: continue
                queries.append(query[12:-4])
                addresses = [b'\x00\x00\x00\x00']
                if query[12:-4] == b'\x08fallback\x04test\x00': addresses.append(b'\x7f\x00\x00\x01')
                response = bytearray(query)
                response[2:4] = b'\x81\x80'; response[6:8] = len(addresses).to_bytes(2, 'big')
                for address in addresses:
                    response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + address
                dns.sendto(response, peer)
        thread = threading.Thread(target=answer); thread.start()
        proc = subprocess.Popen([binary, 'run', '--config', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2): break
                except OSError:
                    if proc.poll() is not None or time.monotonic() >= deadline: raise RuntimeError('proxy did not start')
                    time.sleep(.02)
            target_port = target.getsockname()[1]
            targets = [(b'\x01' + bytes(4), target_port), (b'\x04' + bytes(16), target_port),
                       (b'\x04' + bytes(10) + b'\xff\xff' + bytes(4), target_port),
                       (b'\x03\x09zero.test', target_port), (b'\x01\x7f\x00\x00\x01', 0)]
            for addr, requested_port in targets:
                with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                    client.sendall(b'\x05\x01\x00'); assert exact(client, 2) == b'\x05\x00'
                    client.sendall(b'\x05\x01\x00' + addr + requested_port.to_bytes(2, 'big'))
                    result = exact(client, 10)
                    if result[1] == 0: raise RuntimeError('unspecified target connected')
                try: target.accept()[0].close()
                except TimeoutError: pass
                else: raise RuntimeError('unspecified target reached local listener')
            with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                client.sendall(f'CONNECT 0.0.0.0:{target_port} HTTP/1.1\r\nHost: 0.0.0.0:{target_port}\r\n\r\n'.encode())
                if b' 200 ' in client.recv(1024): raise RuntimeError('HTTP unspecified target connected')
            try: target.accept()[0].close()
            except TimeoutError: pass
            else: raise RuntimeError('HTTP unspecified target reached local listener')
            with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                client.sendall(b'\x05\x01\x00'); assert exact(client, 2) == b'\x05\x00'
                name=b'fallback.test'
                client.sendall(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + target_port.to_bytes(2, 'big'))
                if exact(client, 10)[1] != 0: raise RuntimeError('valid DNS fallback failed')
                with target.accept()[0] as peer:
                    client.sendall(b'ok'); assert exact(peer, 2) == b'ok'
            if queries != [b'\x04zero\x04test\x00', b'\x08fallback\x04test\x00']:
                raise RuntimeError(f'unexpected DNS queries: {queries!r}')
        finally:
            proc.terminate(); proc.wait(timeout=5)
            stop.set(); thread.join(timeout=2)
            proc.stderr.close()


binary = str(pathlib.Path(sys.argv[1]).resolve())
for count in (1, 2): scenario(binary, count)
print('TCP proxy rejects unspecified targets and retries valid DNS candidates')
