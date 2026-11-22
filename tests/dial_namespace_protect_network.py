#!/usr/bin/env python3
"""Validate physical socket namespace and SCM_RIGHTS through the Nexus CLI."""
import argparse
import array
from contextlib import contextmanager
import os
from pathlib import Path
import select
import selectors
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from dns_rule_support import bind_same_port, connect, exact, free_port, nexus_process, udp_client
from udp_bind_port_network import FAMILIES, ORIGIN, certificate, config, wire

SO_NETNS_COOKIE = 71
KINDS = (socket.SOCK_STREAM, socket.SOCK_DGRAM)


def namespace_cookie(sock):
    return sock.getsockopt(socket.SOL_SOCKET, SO_NETNS_COOKIE, 8).hex()


def peer():
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    endpoints = [(family, kind, ORIGIN[family]) for family in FAMILIES for kind in KINDS]
    port, sockets = bind_same_port(endpoints, ipv6_only=True)
    with selectors.DefaultSelector() as reactor:
        for (_, kind, _), server in zip(endpoints, sockets, strict=True):
            if kind == socket.SOCK_STREAM:
                server.listen()
            reactor.register(server, selectors.EVENT_READ, kind)
        print(port, namespace_cookie(sockets[0]), flush=True)
        while True:
            for key, _ in reactor.select():
                server = key.fileobj
                if key.data == socket.SOCK_DGRAM:
                    data, sender = server.recvfrom(65535)
                    if len(data) >= 1200 and data[0] & 0x80:
                        print('initial', sender[0], flush=True)
                        continue
                    server.sendto(data, sender)
                else:
                    client, _ = server.accept()
                    with client:
                        client.settimeout(2)
                        try:
                            data = client.recv(1024)
                            if data:
                                client.sendall(data)
                        except (TimeoutError, ConnectionResetError):
                            pass


@contextmanager
def broker(path, mode):
    observations, errors = [], []
    shutdown = threading.Event()
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen()
        listener.settimeout(.1)

        def serve():
            item = array.array('i').itemsize
            while not shutdown.is_set():
                try:
                    client, _ = listener.accept()
                except TimeoutError:
                    continue
                try:
                    with client:
                        client.settimeout(2)
                        data, control, flags, _ = client.recvmsg(1, socket.CMSG_SPACE(item), socket.MSG_CMSG_CLOEXEC)
                        descriptors = array.array('i')
                        for level, kind, encoded in control:
                            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                                descriptors.frombytes(encoded)
                        try:
                            assert data == b'\x01' and len(descriptors) == 1 and not flags & socket.MSG_CTRUNC
                            with socket.socket(fileno=os.dup(descriptors[0])) as physical:
                                observations.append((physical.type, namespace_cookie(physical), physical.getsockname()[1]))
                            if mode == 'ack':
                                client.sendall(b'\0')
                            elif mode == 'hold':
                                assert client.recv(1) == b'', 'stalled protect request did not time out'
                        finally:
                            for fd in descriptors:
                                os.close(fd)
                except Exception as error:
                    errors.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            yield observations
        finally:
            shutdown.set()
            worker.join(3)
            path.unlink()
            if errors:
                raise errors[0]


def tcp(front, family, port, success=True):
    with connect(front) as client:
        client.sendall(b'\x05\x01\x00')
        assert exact(client, 2) == b'\x05\x00'
        client.sendall(b'\x05\x01\x00' + wire(family, port, b'')[3:])
        version, status, _, address_type = exact(client, 4)
        exact(client, 6 if address_type == 1 else 18)
        assert version == 5 and (status == 0) == success, (family, status, success)
        if success:
            client.sendall(b'dial-netns')
            assert exact(client, 10) == b'dial-netns'
        return status


def udp(front, family, port, success=True):
    with udp_client(front) as (client, relay):
        payload = wire(family, port, b'dial-netns')
        client.settimeout(3 if success else .5)
        client.sendto(payload, relay)
        try:
            received, _ = client.recvfrom(1024)
        except TimeoutError:
            if success:
                raise
        else:
            assert success and received == payload


def hy2(binary, root, origin, port, cookie, fields, path):
    certificate(root)
    password = root / 'password'
    password.write_text('dial-netns')
    password.chmod(0o600)
    front = free_port()
    for inherited in (False, True):
        for family in FAMILIES:
            local = ORIGIN[family]
            own = 'detour "direct";' if inherited else fields
            node = f'''outbound "edge" type="hysteria2" {{ server host="{local}" port={port};
                authentication {{ password-file "{root / 'password'}"; }}
                tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
                {own}
            }}'''
            kdl = root / 'hy2.kdl'
            kdl.write_text(config(front, fields if inherited else '', node))
            with broker(path, 'ack') as allowed, nexus_process(binary, kdl), connect(front) as client:
                client.sendall(b'\x05\x01\x00')
                assert exact(client, 2) == b'\x05\x00'
                client.sendall(b'\x05\x01\x00' + wire(family, 9, b'')[3:])
                assert select.select([origin.stdout], [], [], 4)[0], 'namespace QUIC peer saw no Initial'
                assert origin.stdout.readline().strip() == f'initial {local}'
            assert allowed == [(socket.SOCK_DGRAM, cookie, 0)], allowed
    print('Hysteria 2 sent both Initial families through protected sockets with own binding and direct detour')


def run(binary, deadline_case):
    with tempfile.TemporaryDirectory(prefix='nexus-dial-') as temp:
        root = Path(temp)
        with subprocess.Popen(['unshare', '-n', sys.executable, __file__, '--peer'],
                              stdout=subprocess.PIPE, text=True) as origin:
            try:
                assert select.select([origin.stdout], [], [], 4)[0], 'namespace echo peer did not start'
                port, cookie = origin.stdout.readline().split()
                port = int(port)
                with socket.socket() as host_socket:
                    assert namespace_cookie(host_socket) != cookie
                front = free_port()
                path = root / 'protect.sock'
                namespace_path = f'/proc/{origin.pid}/ns/net'
                kdl = root / 'dial.kdl'
                fields = f'netns "{namespace_path}"; protect-path "{path}"; bind-interface "lo";'
                kdl.write_text(config(front, fields))
                with nexus_process(binary, kdl):
                    tcp(front, socket.AF_INET, port, success=False)
                    with broker(path, 'close') as rejected:
                        tcp(front, socket.AF_INET, port, success=False)
                        udp(front, socket.AF_INET, port, success=False)
                    assert sorted(kind for kind, _, _ in rejected) == sorted(KINDS)
                    with broker(path, 'hold') as stalled:
                        tcp(front, socket.AF_INET, port, success=False)
                    assert stalled == [(socket.SOCK_STREAM, cookie, 0)]
                    with broker(path, 'ack') as allowed:
                        for family in FAMILIES:
                            tcp(front, family, port)
                            udp(front, family, port)
                    assert sorted(allowed) == sorted([(kind, cookie, 0) for kind in KINDS] * 2), allowed
                bad = root / 'bad.kdl'
                bad.write_text(config(front, f'netns "{root}"; protect-path "{path}";'))
                with nexus_process(binary, bad), broker(path, 'ack') as unused:
                    tcp(front, socket.AF_INET, port, success=False)
                    udp(front, socket.AF_INET, port, success=False)
                assert not unused, unused
                hy2(binary, root, origin, port, cookie, fields, path)
                if deadline_case:
                    kdl.write_text(config(front, f'netns "{namespace_path}"; protect-path "{path}"; connect-timeout-ms 65;'))
                    with nexus_process(binary, kdl):
                        with broker(path, 'hold') as stalled:
                            start = time.monotonic()
                            assert tcp(front, socket.AF_INET, port, success=False) == 6
                            assert time.monotonic() - start < .22
                        assert stalled == [(socket.SOCK_STREAM, cookie, 0)]
                        with broker(path, 'ack'):
                            tcp(front, socket.AF_INET, port)
                    print('Protect broker used the shorter connection deadline and recovered on a new connection')
            finally:
                origin.terminate()
                origin.wait(timeout=4)
    print('SOCKS TCP/UDP dual-stack namespace isolation, SCM_RIGHTS before bind, broker rejection and recovery passed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', nargs='?', type=Path)
    parser.add_argument('--inner', action='store_true')
    parser.add_argument('--peer', action='store_true')
    parser.add_argument('--deadline', action='store_true')
    options = parser.parse_args()
    if options.peer:
        peer()
    elif options.inner:
        run(options.binary, options.deadline)
    else:
        extra = ['--deadline'] if options.deadline else []
        subprocess.run(['unshare', '-Ur', sys.executable, __file__, '--inner', str(options.binary.resolve()), *extra], check=True)


if __name__ == '__main__':
    main()
