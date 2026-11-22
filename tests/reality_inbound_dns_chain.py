"""Reality fallback: multi-hop DNS resolution, failure, and shutdown at each hop."""
from test_paths import require_nexus
import pathlib
import os
import select
import socket
import struct
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
NAMES = (b'\x06middle\x04test\x00', b'\x04leaf\x04test\x00', b'\x05cover\x04test\x00')


def udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    sock.settimeout(4)
    return sock


def query(sock, name):
    packet, peer = sock.recvfrom(4096)
    if packet[12:-4] != name or packet[-4:] != b'\x00\x01\x00\x01':
        raise RuntimeError(f'unexpected DNS query: {packet!r}')
    return packet, peer


def reply(sock, packet, peer, success=True):
    flags = b'\x81\x80' if success else b'\x81\x83'
    count = b'\x00\x01' if success else b'\x00\x00'
    answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01' if success else b''
    sock.sendto(packet[:2] + flags + b'\x00\x01' + count + b'\x00\x00\x00\x00' + packet[12:] + answer, peer)


def dns_socket_owned(pid, port):
    owned = set()
    for fd in pathlib.Path(f'/proc/{pid}/fd').iterdir():
        try: target = str(fd.readlink())
        except FileNotFoundError: continue
        if target.startswith('socket:['): owned.add(target[8:-1])
    return any(fields[1].endswith(f':{port:04X}') and fields[9] in owned
               for line in pathlib.Path('/proc/net/udp').read_text().splitlines()[1:]
               if len(fields := line.split()) > 9)


def scenario(mode, stage, guard):
    with tempfile.TemporaryDirectory(prefix='nexus-reality-chain-') as directory, udp_socket() as root, udp_socket() as middle, udp_socket() as leaf, socket.socket() as cover:
        path = pathlib.Path(directory)
        cover.bind(('127.0.0.1', 0)); cover.listen(2); cover.settimeout(3)
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0)); front = reserve.getsockname()[1]
        (path/'secret').write_text('25' + '00'*31 + '\n'); (path/'secret').chmod(0o600)
        (path/'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n'); (path/'uuid').chmod(0o600)
        (path/'server.kdl').write_text(f'''schema-version 1
role "server"
workers 2
dns {{ server "leaf" type="udp" host="leaf.test" port={leaf.getsockname()[1]} domain-resolver="middle"; server "middle" type="udp" host="middle.test" port={middle.getsockname()[1]} domain-resolver="root"; server "root" type="udp" host="127.0.0.1" port={root.getsockname()[1]}; strategy "ipv4_only"; disable-cache #true; }}
inbound "edge" type="vless" {{ listen host="127.0.0.1" port={front}; authentication {{ user "test" uuid-file="{path/'uuid'}"; }}; tls {{ reality {{ private-key-file "{path/'secret'}"; server-name "localhost"; short-id ""; fallback host="cover.test" port={cover.getsockname()[1]}; fallback-resolver "leaf"; }}; }}; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        env = os.environ.copy(); env['LD_PRELOAD'] = str(guard)
        server = subprocess.Popen([require_nexus(), 'run', '--config', path/'server.kdl'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
        try:
            deadline = time.monotonic() + 8
            while True:
                if server.poll() is not None: raise RuntimeError(f'server exited: {server.stderr.read()!r}')
                try:
                    client = socket.create_connection(('127.0.0.1', front), timeout=1)
                    break
                except ConnectionRefusedError:
                    if time.monotonic() > deadline: raise
                    time.sleep(.05)
            with client:
                client.settimeout(5); client.sendall(b'not TLS!')
                sockets = (root, middle, leaf)
                for index, sock in enumerate(sockets):
                    packet, peer = query(sock, NAMES[index])
                    if mode == 'reset' and index == stage:
                        if not dns_socket_owned(server.pid, peer[1]): raise RuntimeError('pending DNS socket not owned')
                        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0)); client.close()
                        limit = time.monotonic() + 3
                        while dns_socket_owned(server.pid, peer[1]):
                            if server.poll() is not None or time.monotonic() > limit: raise RuntimeError('reset did not cancel DNS')
                            time.sleep(.02)
                        reply(sock, packet, peer)
                        break
                    if mode == 'stop' and index == stage:
                        started = time.monotonic(); server.terminate(); server.wait(timeout=5)
                        if server.returncode or time.monotonic()-started > 2: raise RuntimeError('pending DNS did not stop promptly')
                        reply(sock, packet, peer)
                        try: data = client.recv(1)
                        except ConnectionResetError: data = b''
                        if data: raise RuntimeError('client survived stop')
                        break
                    reply(sock, packet, peer, mode != 'reject' or index != stage)
                    if mode == 'reject' and index == stage:
                        try: data = client.recv(1)
                        except ConnectionResetError: data = b''
                        if data: raise RuntimeError('client survived DNS rejection')
                        break
                else:
                    stream, _ = cover.accept(); stream.settimeout(4)
                    with stream:
                        if stream.recv(8) != b'not TLS!': raise RuntimeError('cover received wrong bytes')
                        stream.sendall(b'ok')
                        if client.recv(2) != b'ok': raise RuntimeError('client received wrong response')
                if mode != 'success':
                    for sock in (*sockets[stage+1:], cover):
                        if select.select([sock], [], [], .2)[0]: raise RuntimeError('failed or canceled hop reached next destination')
        finally:
            if server.poll() is None: server.terminate(); server.wait(timeout=5)
            diagnostics = server.stderr.read()
            if server.returncode or b'unexpected-system-resolver' in diagnostics:
                raise RuntimeError(f'server exited {server.returncode}: {diagnostics!r}')
            server.stderr.close()


with tempfile.TemporaryDirectory(prefix='nexus-dns-guard-') as directory:
    guard = pathlib.Path(directory)/'guard.so'
    subprocess.run(['cc', '-shared', '-fPIC', ROOT/'tests/proxy_dns_system_guard.c', '-o', guard], check=True)
    scenario('success', 0, guard)
    for stage in range(3):
        scenario('reject', stage, guard)
        scenario('stop', stage, guard)
        scenario('reset', stage, guard)
print('Reality fallback three-hop DNS success, rejection, shutdown and reset passed')
