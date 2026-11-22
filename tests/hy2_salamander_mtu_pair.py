#!/usr/bin/env python3
"""Nexus Hy2 Salamander client/server in an isolated 1280-byte network."""
import argparse
import json
import contextlib
import errno
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from detour_network import exact, reserve, socks
from dns_rule_support import Echo, nexus_process, udp_client
from hy2_outbound_detour import udp_port
from hy2_outbound_singbox import half_close
from hy2_salamander_singbox import udp_echo
from udp_bind_port_network import certificate


def mtu_drop(front):
    payload = bytes(range(256)) * 512
    errors = []
    with socket.socket() as origin:
        origin.bind(('127.0.0.1', 0)); origin.listen(1); origin.settimeout(10)
        def serve():
            try:
                with origin.accept()[0] as conn:
                    conn.settimeout(12)
                    if exact(conn, 5) != b'ready': raise RuntimeError('preflight mismatch')
                    conn.sendall(b'ready')
                    data = bytearray()
                    while part := conn.recv(16384): data.extend(part)
                    if data != payload: raise RuntimeError(f'origin received {len(data)}/{len(payload)} bytes')
                    conn.sendall(data); conn.shutdown(socket.SHUT_WR)
            except BaseException as error: errors.append(repr(error))
        thread = threading.Thread(target=serve); thread.start()
        try:
            with socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))[0] as client:
                client.settimeout(12); client.sendall(b'ready')
                if exact(client, 5) != b'ready': raise RuntimeError('preflight reply mismatch')
                time.sleep(5)
                subprocess.run(['ip', 'link', 'set', 'lo', 'mtu', '1280'], check=True)
                print('lowered established path MTU to 1280', flush=True)
                client.sendall(payload); client.shutdown(socket.SHUT_WR)
                if exact(client, len(payload)) != payload or client.recv(1): raise RuntimeError('response mismatch')
        finally:
            thread.join(15)
        if thread.is_alive() or errors: raise RuntimeError(f'origin failed: {errors!r}')


def mtu_drop_datagram(front, echo):
    address = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + echo.port.to_bytes(2, 'big')
    large = b'low-mtu-datagram:' + bytes(range(256)) * 5
    with udp_client(front) as (client, relay):
        def exchange(payload):
            packet = address + payload
            client.sendto(packet, relay)
            if client.recvfrom(65535)[0] != packet: raise RuntimeError('UDP reply mismatch')

        client.settimeout(8); exchange(b'before-drop')
        time.sleep(5)
        subprocess.run(['ip', 'link', 'set', 'lo', 'mtu', '1280'], check=True)
        print(f'{time.time():.6f} lowered MTU; testing same UDP association', flush=True)
        exchange(large)
        exchange(b'after-drop')
        exchange(b'fragmented-after-drop:' + bytes(range(256)) * 16)
        client.settimeout(1)
        try:
            response = client.recvfrom(65535)[0]
            raise RuntimeError(f'unexpected extra UDP reply: {len(response)} bytes')
        except TimeoutError:
            pass
        if echo.received.count(large) != 1: raise RuntimeError('target did not receive exactly one large UDP payload')
        print(f'{time.time():.6f} same UDP association passed after MTU drop', flush=True)



def mtu_drop_restore(front):
    payload = bytes(range(256)) * 512
    errors = []
    with socket.socket() as origin:
        origin.bind(('127.0.0.1', 0)); origin.listen(1); origin.settimeout(10)
        def serve():
            try:
                with origin.accept()[0] as conn:
                    conn.settimeout(15)
                    for label, size in ((b'R', 1), (b'L', len(payload)), (b'H', len(payload))):
                        data = exact(conn, size)
                        if data != (label if size == 1 else payload): raise RuntimeError('origin data mismatch')
                        conn.sendall(data)
                    if conn.recv(1): raise RuntimeError('missing FIN')
                    conn.shutdown(socket.SHUT_WR)
            except BaseException as error: errors.append(repr(error))
        thread = threading.Thread(target=serve); thread.start()
        try:
            with socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))[0] as client:
                client.settimeout(15); client.sendall(b'R')
                if exact(client, 1) != b'R': raise RuntimeError('preflight mismatch')
                time.sleep(5)
                subprocess.run(['ip', 'link', 'set', 'lo', 'mtu', '1280'], check=True)
                print(f'{time.time():.6f} lowered MTU', flush=True)
                client.sendall(payload)
                if exact(client, len(payload)) != payload: raise RuntimeError('low MTU response mismatch')
                subprocess.run(['ip', 'link', 'set', 'lo', 'mtu', '1500'], check=True)
                print(f'{time.time():.6f} restored MTU', flush=True)
                time.sleep(4)
                client.sendall(payload); client.shutdown(socket.SHUT_WR)
                if exact(client, len(payload)) != payload or client.recv(1): raise RuntimeError('restored response mismatch')
        finally:
            thread.join(20)
        if thread.is_alive() or errors: raise RuntimeError(f'origin failed: {errors!r}')


def mtu_delayed_restore(front):
    # Keep the same QUIC stream alive past the production ten-minute reprobe.
    payload = bytes(range(256)) * 512
    errors = []
    with socket.socket() as origin:
        origin.bind(('127.0.0.1', 0)); origin.listen(1); origin.settimeout(10)
        def serve():
            try:
                with origin.accept()[0] as conn:
                    conn.settimeout(20)
                    while True:
                        command = conn.recv(1)
                        if not command: break
                        size = len(payload) if command == b'B' else 1
                        data = exact(conn, size)
                        if data != (payload if command == b'B' else b'K'): raise RuntimeError('origin data mismatch')
                        conn.sendall(data)
                    conn.shutdown(socket.SHUT_WR)
            except BaseException as error: errors.append(repr(error))
        thread = threading.Thread(target=serve); thread.start()
        try:
            with socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))[0] as client:
                client.settimeout(20)
                def exchange(command, data):
                    client.sendall(command + data)
                    if exact(client, len(data)) != data: raise RuntimeError('response mismatch')
                exchange(b'K', b'K'); time.sleep(5)
                subprocess.run(['ip', 'link', 'set', 'lo', 'mtu', '1280'], check=True)
                dropped = time.monotonic(); print(f'{time.time():.6f} lowered MTU', flush=True)
                exchange(b'B', payload)
                # Give native low-MTU probes time to exhaust before restoring.
                for _ in range(4): time.sleep(3); exchange(b'K', b'K')
                subprocess.run(['ip', 'link', 'set', 'lo', 'mtu', '1500'], check=True)
                print(f'{time.time():.6f} restored MTU after low-path probes', flush=True)
                exchange(b'B', payload)
                print(f'{time.time():.6f} pre-reprobe transfer complete', flush=True)
                while time.monotonic() < dropped + 606:
                    time.sleep(5); exchange(b'K', b'K')
                print(f'{time.time():.6f} post-reprobe transfer', flush=True)
                exchange(b'B', payload); client.shutdown(socket.SHUT_WR)
                if client.recv(1): raise RuntimeError('missing FIN')
        finally:
            thread.join(22)
        if thread.is_alive() or errors: raise RuntimeError(f'origin failed: {errors!r}')


def mtu_drop_parallel(front, stop_process=None):
    count = 3
    payloads = [bytes((byte + index) % 256 for byte in range(256)) * 512 for index in range(count)]
    errors = []
    active = threading.Event()
    stopping = threading.Event()
    with socket.socket() as origin, contextlib.ExitStack() as stack:
        origin.bind(('127.0.0.1', 0)); origin.listen(count); origin.settimeout(10)
        def serve(conn):
            try:
                with conn:
                    conn.settimeout(15)
                    index = exact(conn, 1)[0]
                    if index >= count: raise RuntimeError('invalid connection identity')
                    conn.sendall(bytes([index]))
                    data = bytearray(); received = 0
                    while part := conn.recv(16384):
                        if stop_process:
                            received += len(part)
                            if received >= 16384: active.set()
                        else: data.extend(part)
                    if not stop_process:
                        if data != payloads[index]: raise RuntimeError(f'connection {index}: received {len(data)} bytes')
                        conn.sendall(data); conn.shutdown(socket.SHUT_WR)
            except (OSError, RuntimeError) as error:
                if not stopping.is_set(): errors.append(repr(error))
        clients = []
        threads = []
        for index in range(count):
            client = stack.enter_context(socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))[0])
            client.settimeout(15); clients.append(client)
            conn, _ = origin.accept()
            thread = threading.Thread(target=serve, args=(conn,)); thread.start(); threads.append(thread)
            client.sendall(bytes([index]))
            if exact(client, 1) != bytes([index]): raise RuntimeError('preflight reply mismatch')
        time.sleep(5)
        subprocess.run(['ip', 'link', 'set', 'lo', 'mtu', '1280'], check=True)
        print(f'lowered established path MTU to 1280 with {count} connections', flush=True)
        def transfer(index, client):
            try:
                if stop_process:
                    while not stopping.is_set(): client.sendall(payloads[index])
                else:
                    client.sendall(payloads[index]); client.shutdown(socket.SHUT_WR)
                    if exact(client, len(payloads[index])) != payloads[index] or client.recv(1):
                        raise RuntimeError(f'connection {index}: response mismatch')
            except (OSError, RuntimeError) as error:
                if not stopping.is_set(): errors.append(repr(error))
        transfers = [threading.Thread(target=transfer, args=(index, client)) for index, client in enumerate(clients)]
        for thread in transfers: thread.start()
        if stop_process:
            if not active.wait(12): raise RuntimeError(f'no transfer after MTU drop: {errors!r}')
            stopping.set()
            started = time.monotonic(); stop_process.terminate(); stop_process.wait(timeout=5)
            if stop_process.returncode: raise RuntimeError(f'active stop exit {stop_process.returncode}')
            print(f'active process drained in {time.monotonic() - started:.3f}s', flush=True)
            for client in clients:
                try: client.shutdown(socket.SHUT_RDWR)
                except OSError as error:
                    if error.errno != errno.ENOTCONN: raise
        for thread in transfers: thread.join(20)
        for thread in threads: thread.join(20)
        if any(thread.is_alive() for thread in transfers + threads) or errors:
            raise RuntimeError(f'parallel transfer failed: {errors!r}')


def run(binary, mtu, hold, plain, drop, parallel, stop, restore, delayed, datagram_drop, family_filter, payload_limit, disable_pmtud, quic_side):
    with tempfile.TemporaryDirectory(prefix='hy2-mtu-pair-') as directory:
        root = Path(directory); certificate(root)
        for name, value in (('password', 'test-password'), ('obfs', 'salamander-secret')):
            path = root / name; path.write_text(value + '\n'); path.chmod(0o600)
        for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            if family_filter and family_filter != (4 if family == socket.AF_INET else 6): continue
            port, front = udp_port(host), reserve()
            server, client = root / 'server.kdl', root / 'client.kdl'
            def quic_config(side):
                fields = []
                if not plain: fields.append(f'salamander-password-file "{root / "obfs"}";')
                if quic_side in ('both', side):
                    if payload_limit is not None: fields.append(f'max-udp-payload-size {payload_limit};')
                    if disable_pmtud: fields.append('disable-path-mtu-discovery #true;')
                return 'quic { ' + ' '.join(fields) + ' }' if fields else ''
            server_quic, client_quic = quic_config('server'), quic_config('client')
            print(f'QUIC IPv{4 if family == socket.AF_INET else 6} server port {port}', flush=True)
            server.write_text(f'''schema-version 1
role "server"
workers 2
inbound "edge" type="hysteria2" {{ listen host="{host}" port={port};
 authentication {{ user "test" password-file="{root / 'password'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
 {server_quic}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
            client.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{ server host="{host}" port={port}; udp-fragment #false;
 authentication {{ password-file "{root / 'password'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
 {client_quic}
}}
routing {{ default-outbound "edge"; }}
''')
            with Echo() as echo, nexus_process(str(binary), str(server)) as server_process, nexus_process(str(binary), str(client)) as client_process:
                if delayed: mtu_delayed_restore(front)
                elif restore: mtu_drop_restore(front)
                elif parallel: mtu_drop_parallel(front, {"client": client_process, "server": server_process}.get(stop))
                elif datagram_drop: mtu_drop_datagram(front, echo)
                elif drop: mtu_drop(front)
                else:
                    half_close(front); udp_echo(front, echo.port, hold)
                    if hold and (payload_limit is not None or disable_pmtud): half_close(front)
            if drop or parallel or restore or delayed or datagram_drop: subprocess.run(['ip', 'link', 'set', 'lo', 'mtu', str(mtu)], check=True)
            if restore or delayed:
                print(f'IPv{4 if family == socket.AF_INET else 6}: low and restored MTU reliable streams passed', flush=True)
            elif parallel:
                with socket.socket(family, socket.SOCK_DGRAM) as check:
                    check.bind((host, port))
                print(f'IPv{4 if family == socket.AF_INET else 6}: parallel {stop or "TCP/FIN"} passed; server UDP port released', flush=True)
            elif datagram_drop:
                print(f'IPv{4 if family == socket.AF_INET else 6}: UDP continued after MTU drop', flush=True)
            else:
                print(f'{mtu} MTU Nexus {"plain" if plain else "Salamander"} IPv{4 if family == socket.AF_INET else 6}: TCP/FIN and dual-family UDP passed', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--isolated', action='store_true')
    parser.add_argument('--mtu', type=int, default=1280, choices=(1280, 1500))
    parser.add_argument('--hold', type=int, default=0, choices=(0, 5))
    parser.add_argument('--plain', action='store_true')
    parser.add_argument('--drop', action='store_true', help='lower an established path from MTU 1500 to 1280')
    parser.add_argument('--datagram-drop', action='store_true', help='exercise UDP after an established path MTU drop')
    parser.add_argument('--parallel', action='store_true', help='exercise multiple established connections')
    parser.add_argument('--restore', action='store_true', help='drop and restore path MTU during a stream')
    parser.add_argument('--stop', choices=('client', 'server'), help='stop during parallel traffic')
    parser.add_argument('--delayed-restore', action='store_true', help='exercise the real ten-minute reprobe')
    parser.add_argument('--family', type=int, choices=(4, 6))
    parser.add_argument('--payload-limit', type=int)
    parser.add_argument('--disable-pmtud', action='store_true')
    parser.add_argument('--quic-side', choices=('both', 'client', 'server'), default='both')
    args = parser.parse_args()
    if args.stop and not args.parallel: parser.error('--stop requires --parallel')
    if sum((args.restore, args.delayed_restore, args.drop, args.datagram_drop, args.parallel)) > 1: parser.error('select one MTU scenario')
    binary = args.binary.resolve(strict=True)
    if not args.isolated:
        command = ['unshare', '-Urn', 'bash', '-c', 'ip link set lo up && ip link set lo mtu "$3" && shift 3 && exec python3 "$@"',
                   'hy2-mtu-test', str(Path(__file__).resolve()), str(binary), str(args.mtu),
                   str(Path(__file__).resolve()), str(binary), '--isolated', '--mtu', str(args.mtu), '--hold', str(args.hold)]
        if args.plain: command.append('--plain')
        if args.drop: command.append('--drop')
        if args.datagram_drop: command.append('--datagram-drop')
        if args.parallel: command.append('--parallel')
        if args.restore: command.append('--restore')
        if args.delayed_restore: command.append('--delayed-restore')
        if args.family: command.extend(['--family', str(args.family)])
        if args.payload_limit is not None: command.extend(['--payload-limit', str(args.payload_limit)])
        if args.disable_pmtud: command.append('--disable-pmtud')
        command.extend(['--quic-side', args.quic_side])
        if args.stop: command.extend(['--stop', args.stop])
        subprocess.run(command, check=True)
    else:
        link = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'lo'], text=True))
        if link[0]['mtu'] != args.mtu: raise RuntimeError('loopback MTU does not match')
        if (args.drop or args.datagram_drop or args.parallel or args.restore or args.delayed_restore) and args.mtu != 1500: parser.error('MTU drop scenarios require --mtu 1500')
        run(binary, args.mtu, args.hold, args.plain, args.drop, args.parallel, args.stop, args.restore, args.delayed_restore, args.datagram_drop, args.family, args.payload_limit, args.disable_pmtud, args.quic_side)
