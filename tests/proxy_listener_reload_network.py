#!/usr/bin/env python3
"""Exercise staged ordinary TCP listeners through the production CLI."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import select
import signal
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time

from dns_rule_support import exact, nexus_process


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(4096):
            self.request.sendall(data)


def config(path, workers, bindings):
    lines = ["schema-version 1", 'role "client"', f"workers {workers}", "shutdown-grace-ms 2000", 'log { privacy "verbose"; }']
    for name, port, password in bindings:
        auth = 'authentication "none"' if password is None else (
            f'authentication "password" username="alice" password-file="{password}"')
        lines.append(f'inbound "{name}" type="socks5" {{ listen host="127.0.0.1" port={port}; {auth}; }}')
    lines.extend(['outbound "direct" type="direct"', 'routing { default-outbound "direct"; }'])
    candidate = path.with_suffix(".candidate")
    candidate.write_text("\n".join(lines) + "\n")
    candidate.replace(path)


def reload(process, failure=None):
    process.send_signal(signal.SIGHUP)
    deadline = time.monotonic() + 8
    diagnostics = []
    while time.monotonic() < deadline:
        if not select.select([process.stderr], [], [], max(0, deadline - time.monotonic()))[0]:
            break
        line = process.stderr.readline()
        if not line:
            break
        diagnostics.append(line)
        _, _, message = line.partition(b" generation=")
        if message:
            _, _, line = message.partition(b" ")
        if line == b"traffic rules reloaded\n" and failure is None:
            return
        if line.startswith(b"listeners reloaded generation=") and failure is None:
            return int(line.removeprefix(b"listeners reloaded generation="))
        if line.startswith(b"traffic rule reload failed:") and failure is not None and failure in line:
            return
        if line.startswith((b"traffic rules reloaded", b"listeners reloaded", b"traffic rule reload failed:")):
            break
    raise AssertionError(f"unexpected reload result: {diagnostics!r}")


def socks(front, origin, password=None):
    client = socket.create_connection(("127.0.0.1", front), timeout=3)
    try:
        client.sendall(b"\x05\x01" + (b"\x00" if password is None else b"\x02"))
        assert exact(client, 2) == (b"\x05\x00" if password is None else b"\x05\x02")
        if password is not None:
            client.sendall(b"\x01\x05alice" + bytes([len(password)]) + password)
            assert exact(client, 2) == b"\x01\x00"
        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", origin))
        reply = exact(client, 4)
        assert reply[:3] == b"\x05\x00\x00" and reply[3] in (1, 4), reply
        exact(client, 6 if reply[3] == 1 else 18)
        return client
    except BaseException:
        client.close()
        raise


def echo(client, message):
    client.sendall(message)
    assert exact(client, len(message)) == message


def refused(port):
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                pass
        except (ConnectionRefusedError, ConnectionResetError):
            return
        time.sleep(.01)
    raise AssertionError(f"retired or rolled-back listener remains open at {port}")


def check(binary, root, origin, workers):
    path = root / "proxy.kdl"
    secret = root / "password"
    secret.write_bytes(b"new-password")
    secret.chmod(0o600)
    reserves = [socket.socket() for _ in range(5)]
    try:
        for reserve in reserves:
            reserve.bind(("127.0.0.1", 0))
        same, removed, added, rolled_back, occupied = [s.getsockname()[1] for s in reserves]
        for reserve in reserves[:-1]:
            reserve.close()
        reserves[-1].listen()
        initial = [("keep", same, None), ("remove", removed, None)]
        replacement = [("keep", same, secret), ("add", added, None)]
        config(path, workers, initial)
        with nexus_process(binary, path, listeners=2) as process:
            with socks(same, origin) as established, socks(removed, origin) as established_removed:
                config(path, workers, replacement + [("staged", rolled_back, None), ("conflict", occupied, None)])
                reload(process, b"cannot stage TCP port")
                refused(added)
                refused(rolled_back)
                with socks(same, origin) as fresh, socks(removed, origin) as still_open:
                    echo(fresh, b"same bind still uses old settings")
                    echo(still_open, b"removed listener stayed active after rollback")
                config(path, workers, [("keep", same, root / "missing"), ("add", added, None)])
                reload(process, b"invalid TCP listener keep")
                echo(established, b"prepare failure preserved the established flow")
                with socks(same, origin) as fresh:
                    echo(fresh, b"prepare failure preserved admission")

                config(path, workers, replacement)
                reload(process)
                echo(established, b"same bind preserved its admitted stream")
                echo(established_removed, b"removed listener preserved its admitted stream")
                refused(removed)
                with socket.create_connection(("127.0.0.1", same), timeout=3) as old_greeting:
                    old_greeting.sendall(b"\x05\x01\x00")
                    assert exact(old_greeting, 2) == b"\x05\xff"
                with socks(added, origin) as fresh:
                    echo(fresh, b"new listener relayed traffic")

                def challenge(index):
                    with socks(same, origin, b"new-password") as client:
                        echo(client, str(index).encode())

                with ThreadPoolExecutor(max_workers=8) as executor:
                    list(executor.map(challenge, range(24)))
                assert established.recv(1) == b"", "retired generation exceeded its drain deadline"
                assert established_removed.recv(1) == b"", "removed listener exceeded its drain deadline"
                config(path, workers, initial)
                reload(process)
                with socks(removed, origin) as reopened:
                    echo(reopened, b"retired port can be rebound")
                refused(added)
    finally:
        for reserve in reserves:
            reserve.close()


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="nexus-listener-reload-") as directory, \
         socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler) as origin:
        thread = threading.Thread(target=origin.serve_forever)
        thread.start()
        try:
            for workers in (1, 2):
                check(binary, Path(directory), origin.server_address[1], workers)
                print(f"{workers} worker(s): same-bind replacement, add/remove, rollback, and old-flow drain passed")
        finally:
            origin.shutdown()
            thread.join()
