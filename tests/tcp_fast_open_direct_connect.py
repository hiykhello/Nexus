#!/usr/bin/env python3
"""Check direct CONNECT prefetch, failure and SOCKS read-first behavior."""
import pathlib
import socket
import struct
import sys
import tempfile
import threading

from dns_rule_support import connect, exact, free_port, nexus_process

binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='nexus-direct-tfo-connect-') as directory:
    root = pathlib.Path(directory)
    front = free_port()
    config = root / 'client.kdl'
    config.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{ tcp-fast-open #true; }}
routing {{ default-outbound "direct"; }}
''')
    with nexus_process(binary, config):
        for mode in ('prefetched', 'read-first'):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(5)
                port = listener.getsockname()[1]
                errors = []
                def serve():
                    try:
                        with listener.accept()[0] as peer:
                            peer.settimeout(5)
                            if mode == 'read-first':
                                peer.sendall(b'hello')
                            else:
                                data = exact(peer, 4096)
                                if data != bytes(range(256)) * 16:
                                    raise RuntimeError('prefetched data changed or duplicated')
                                peer.sendall(data)
                    except Exception as error:
                        errors.append(repr(error))
                thread = threading.Thread(target=serve)
                thread.start()
                with connect(front) as client:
                    client.settimeout(5)
                    if mode == 'prefetched':
                        data = bytes(range(256)) * 16
                        client.sendall(f'CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n'.encode() + data)
                        header = bytearray()
                        while not header.endswith(b'\r\n\r\n'):
                            header.extend(exact(client, 1))
                        if not header.startswith(b'HTTP/1.1 200') or exact(client, len(data)) != data:
                            raise RuntimeError('CONNECT lost prefetched data')
                    else:
                        client.sendall(b'\x05\x01\x00')
                        if exact(client, 2) != b'\x05\x00':
                            raise RuntimeError('SOCKS greeting failed')
                        client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', port))
                        reply = exact(client, 10)
                        if reply[:2] != b'\x05\x00' or exact(client, 5) != b'hello':
                            raise RuntimeError('SOCKS read-first connection failed')
                thread.join(5)
                if thread.is_alive() or errors:
                    raise RuntimeError(f'{mode} peer failed: {errors}')
        refused = free_port()
        with connect(front) as client:
            client.settimeout(5)
            client.sendall(f'CONNECT 127.0.0.1:{refused} HTTP/1.1\r\nHost: 127.0.0.1:{refused}\r\n\r\nextra'.encode())
            if not client.recv(4096).startswith(b'HTTP/1.1 502'):
                raise RuntimeError('refused CONNECT did not report failure')
print('direct CONNECT prefetched data, SOCKS read-first and refused connection passed')
