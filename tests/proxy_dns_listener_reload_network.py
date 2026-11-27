#!/usr/bin/env python3
"""Exercise DNS listener publication and in-flight query ownership."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from dns_rule_support import DnsPeer, bind_same_port, exact, free_port, nexus_process, wire_name
from proxy_listener_reload_network import refused, reload


class AddressPeer(DnsPeer):
    def __init__(self, address):
        super().__init__()
        self.address = socket.inet_aton(address)

    def reply(self, packet, transport):
        response = super().reply(packet, transport)
        if response and struct.unpack_from("!H", response, 6)[0]:
            return response[:-4] + self.address
        return response


def configure(path, proxy_port, dns_port=None, upstream=None, dns_host="127.0.0.1"):
    source = f'''schema-version 1
role "client"
workers 2
shutdown-grace-ms 2000
log {{ privacy "verbose"; }}
control socket="{path.parent / 'control.sock'}"
inbound "front" type="socks5" {{ listen host="127.0.0.1" port={proxy_port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
'''
    if dns_port is not None:
        source += f'''dns {{
    listen host="{dns_host}" port={dns_port}
    server "res" type="udp" host="127.0.0.1" port={upstream}
    final "res"
    strategy "ipv4_only"
}}
'''
    candidate = path.with_suffix(".candidate")
    candidate.write_text(source)
    candidate.replace(path)


def query(name, port=0, stream=None, host="127.0.0.1"):
    packet = struct.pack("!6H", 0x5678, 0x100, 1, 0, 0, 0) + wire_name(name) + struct.pack("!2H", 1, 1)
    if stream is not None:
        stream.sendall(struct.pack("!H", len(packet)) + packet)
        response = exact(stream, struct.unpack("!H", exact(stream, 2))[0])
    else:
        with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.connect((host, port))
            client.send(packet)
            response = client.recv(1024)
    identifier, flags, questions, answers = struct.unpack_from("!4H", response)
    assert identifier == 0x5678 and flags & 15 == 0 and questions == answers == 1, response
    return socket.inet_ntoa(response[-4:])


def wait_for_query(upstream, name):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if upstream.count(name, 1):
            return
        time.sleep(.01)
    raise AssertionError(f"query {name} did not reach its original upstream")


def generation(binary, directory, expected):
    status = subprocess.check_output([binary, "control", directory / "control.sock", "status"], timeout=3, text=True)
    assert f"listener-generation={expected}" in status.splitlines(), status


def verify(binary, directory, first, second):
    path = directory / "config.kdl"
    with socket.socket(socket.AF_INET6) as reserved:
        reserved.bind(("::1", 0))
        moved = reserved.getsockname()[1]
    conflict, (tcp_check, occupied) = bind_same_port((
        (socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1"),
        (socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1"),
    ))
    with tcp_check, occupied:
        front, original = free_port(), free_port()
        while original == front:
            original = free_port()

        configure(path, front)
        with nexus_process(binary, path) as process, ThreadPoolExecutor(max_workers=1) as thread:
            generation(binary, directory, 1)
            configure(path, front, conflict, first.port)
            # Leave TCP free so staging reaches the deliberately occupied UDP socket.
            tcp_check.close()
            reload(process, b"DNS UDP listen")
            refused(conflict)
            generation(binary, directory, 1)
            configure(path, front, original, first.port)
            assert reload(process) == 2
            generation(binary, directory, 2)
            assert query("cache.test", original) == "192.0.2.10"

            with socket.create_connection(("127.0.0.1", original), timeout=3) as persistent:
                assert query("tcp.test", stream=persistent) == "192.0.2.10"
                gate = first.gates[("held.test", 1)] = threading.Event()
                pending = thread.submit(query, "held.test", original)
                try:
                    wait_for_query(first, "held.test")
                    configure(path, front, original, second.port)
                    assert reload(process) == 3
                    assert query("cache.test", original) == "192.0.2.20"
                    assert query("tcp.test", stream=persistent) == "192.0.2.20"
                    assert not pending.done()
                finally:
                    gate.set()
                assert pending.result() == "192.0.2.10"

                gate = second.gates[("moving.test", 1)] = threading.Event()
                pending = thread.submit(query, "moving.test", original)
                try:
                    wait_for_query(second, "moving.test")
                    configure(path, front, moved, first.port, "::1")
                    assert reload(process) == 4
                    refused(original)
                    assert query("new.test", moved, host="::1") == "192.0.2.10"
                    assert not pending.done()
                finally:
                    gate.set()
                assert pending.result() == "192.0.2.20"
                assert query("retired.test", stream=persistent) == "192.0.2.20"
                assert persistent.recv(1) == b""
            with socket.create_connection(("::1", moved), timeout=3) as client:
                assert query("v6.test", stream=client) == "192.0.2.10"
            configure(path, front)
            assert reload(process) == 5
            generation(binary, directory, 5)
            with socket.socket(socket.AF_INET6) as closed_tcp, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as closed_udp:
                assert closed_tcp.connect_ex(("::1", moved)) != 0
                deadline = time.monotonic() + 1
                while True:
                    try:
                        closed_udp.bind(("::1", moved))
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(.01)


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="nexus-dns-listener-reload-") as directory, \
         AddressPeer("192.0.2.10") as first, AddressPeer("192.0.2.20") as second:
        verify(binary, Path(directory), first, second)
    print("DNS TCP/UDP binding rollback, same-port upstream switch, IPv6 move, old-query drain, and removal passed")
