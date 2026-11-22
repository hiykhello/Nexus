"""Exercise fallback prefix ordering, duplex backpressure, and half-close."""
from test_paths import optional_fixture
import argparse
import pathlib
import socket
import subprocess
import tempfile
import threading

root = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fixture', type=pathlib.Path,
                    default=optional_fixture('reality-fallback-fixture'), required=optional_fixture('reality-fallback-fixture') is None)
fixture = parser.parse_args().fixture.resolve()
prefix = bytes(range(256)) * 300
upload = bytes(range(255, -1, -1)) * 1200
download = b'cover-response\x00' * 12000

def read_to_eof(sock):
    data = bytearray()
    while True:
        part = sock.recv(8192)
        if not part:
            return bytes(data)
        data.extend(part)

with tempfile.TemporaryDirectory(prefix='nexus-reality-fallback-') as directory:
    path = pathlib.Path(directory) / 'prefix'
    path.write_bytes(prefix)
    client, server = socket.socketpair()
    target, cover = socket.socketpair()
    for sock in (client, target): sock.settimeout(8)
    process = subprocess.Popen([fixture, str(server.fileno()), str(cover.fileno()), path],
                               pass_fds=(server.fileno(), cover.fileno()))
    server.close(); cover.close()
    errors = []
    def origin():
        try:
            target.sendall(download)
            target.shutdown(socket.SHUT_WR)
            if read_to_eof(target) != prefix + upload: raise AssertionError('upload changed or prefix reordered')
        except BaseException as error: errors.append(error)
    thread = threading.Thread(target=origin)
    thread.start()
    try:
        def send():
            try: client.sendall(upload); client.shutdown(socket.SHUT_WR)
            except BaseException as error: errors.append(error)
        writer = threading.Thread(target=send); writer.start()
        if read_to_eof(client) != download: raise AssertionError('download changed')
        writer.join(8); thread.join(8)
        if writer.is_alive() or thread.is_alive(): raise AssertionError('relay did not drain')
        if errors: raise errors[0]
        if process.wait(timeout=8): raise AssertionError('relay failed')
    finally:
        client.close(); target.close()
        if process.poll() is None: process.kill(); process.wait()
        thread.join(8)
    # Leave the receiver idle so the prefix write blocks, then cancel both
    # directions and require the owner to drain them before returning.
    path.write_bytes(prefix * 32)
    client, server = socket.socketpair()
    target, cover = socket.socketpair()
    process = subprocess.Popen([fixture, str(server.fileno()), str(cover.fileno()), path, 'cancel'],
                               pass_fds=(server.fileno(), cover.fileno()))
    server.close(); cover.close()
    try:
        if process.wait(timeout=5): raise AssertionError('blocked relay did not cancel and drain')
    finally:
        client.close(); target.close()
        if process.poll() is None: process.kill(); process.wait()
print('Reality fallback prefix, duplex data, half-close, and cancellation passed')
