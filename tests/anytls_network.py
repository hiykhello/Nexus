#!/usr/bin/env python3
"""Actual TLS AnyTLS streams against the fixed sing-box in both directions."""
import argparse
import contextlib
import json
import pathlib
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time

from dns_rule_support import exact, free_port
from detour_network import running


class Origin:
    def __init__(self, expected=3, idle_timeout=5):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.closed, self.errors, self.peers, self.expected = 0, [], [], expected
        self.idle_timeout = idle_timeout
        self.condition, self.stop = threading.Condition(), threading.Event()

    def echo(self, client):
        try:
            with client:
                client.settimeout(self.idle_timeout)
                while data := client.recv(65535):
                    client.sendall(data)
                client.shutdown(socket.SHUT_WR)
        except Exception as error:
            self.errors.append(error)
        finally:
            with self.condition:
                self.closed += 1
                self.condition.notify_all()

    def serve(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            peer = threading.Thread(target=self.echo, args=(client,))
            peer.start()
            self.peers.append(peer)

    def wait(self):
        with self.condition:
            if not self.condition.wait_for(lambda: self.closed == self.expected, timeout=5) or self.errors:
                raise RuntimeError(f"logical stream targets did not close: {self.closed}, {self.errors}")

    def __enter__(self):
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()
        return self

    def __exit__(self, kind, *_):
        self.stop.set()
        self.thread.join(2)
        self.listener.close()
        for peer in self.peers:
            peer.join(6)
        if kind is None and (self.errors or self.thread.is_alive() or any(peer.is_alive() for peer in self.peers)):
            raise RuntimeError(f"origin failure: {self.errors}")


def line(process, expected):
    if not select.select([process.stdout], [], [], 8)[0] or process.stdout.readline().strip() != expected:
        raise RuntimeError(f"AnyTLS fixture did not report {expected!r}; exit={process.poll()}")


def client_fixture(fixture, root, backend, pool_fixture=None):
    front = free_port()
    config = root / "server.json"
    config.write_text(json.dumps({"log": {"level": "warn"}, "inbounds": [{"type": "anytls", "listen": "127.0.0.1", "listen_port": front,
        "users": [{"name": "client", "password": "anytls-network-secret"}],
        "tls": {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")}}], "outbounds": [{"type": "direct"}]}))
    with running(["sing-box", "run", "-c", config], front, root / "box-server.log"), Origin() as origin:
        process = subprocess.Popen([fixture, "client", str(front), str(origin.port), str(root / "cert"), str(root / "key"), str(root / "password"), str(backend)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            line(process, b"streams-done")
            origin.wait()
            stdout, stderr = process.communicate(b"x", timeout=5)
            if process.returncode:
                raise RuntimeError(f"AnyTLS client failed: {process.returncode} {stdout!r} {stderr!r}")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)
        for mode in ("pool-idle", "pool-active", "pool-queued"):
            with Origin(expected=1 if mode == "pool-active" else 0) as target:
                abandoned = subprocess.run([fixture, mode, str(front), str(target.port), str(root / "cert"), str(root / "key"), str(root / "password"), str(backend)],
                                           capture_output=True, timeout=10)
                if abandoned.returncode or abandoned.stdout.strip() != b"pool-abandoned":
                    raise RuntimeError(f"AnyTLS {mode} abandonment: {abandoned.returncode} {abandoned.stdout!r} {abandoned.stderr!r}")
                target.wait()
        if pool_fixture:
            for mode in ("warm", "recover", "waiter-stop", "starting-stop", "waiter-cancel", "starting-cancel", "idle-abandon", "active-abandon", "starting-abandon", "queued-abandon"):
                expected = 2 if mode == "warm" else 1 if mode in ("active-abandon", "waiter-cancel", "starting-cancel") else 0
                with Origin(expected=expected) as target:
                    checked = subprocess.run([pool_fixture, mode, str(front), str(target.port), str(root / "cert"), str(root / "key"),
                                              str(root / "password"), str(backend)], capture_output=True, timeout=12)
                    if checked.returncode or checked.stdout.strip() != b"pool-passed":
                        raise RuntimeError(f"AnyTLS automatic pool {mode}: {checked.returncode} {checked.stdout!r} {checked.stderr!r}")
                    target.wait()
                print(f"AnyTLS automatic pool {mode} passed: backend={backend}", flush=True)


def server_fixture(fixture, root, backend):
    front, socks = free_port(), free_port()
    config = root / "client.json"
    config.write_text(json.dumps({"log": {"level": "warn"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks}],
        "outbounds": [{"type": "anytls", "server": "127.0.0.1", "server_port": front, "password": "anytls-network-secret", "min_idle_session": 1,
                       "tls": {"enabled": True, "server_name": "localhost", "certificate_path": str(root / "cert")}}]}))
    with Origin() as origin:
        process = subprocess.Popen([fixture, "server", str(front), str(origin.port), str(root / "cert"), str(root / "key"), str(root / "password"), str(backend)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            line(process, b"ready")
            with running(["sing-box", "run", "-c", config], socks, root / "box-client.log"):
                for index in range(3):
                    with socket.create_connection(("127.0.0.1", socks), timeout=5) as client:
                        client.sendall(b"\x05\x01\x00")
                        if exact(client, 2) != b"\x05\x00":
                            raise RuntimeError("SOCKS negotiation")
                        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", origin.port))
                        reply = exact(client, 4)
                        if reply[1] or reply[3] not in (1, 4):
                            raise RuntimeError(f"AnyTLS SOCKS connect: {reply!r}")
                        exact(client, 6 if reply[3] == 1 else 18)
                        payload = bytes((i + index) % 256 for i in range(16384))
                        client.sendall(payload)
                        if exact(client, len(payload)) != payload:
                            raise RuntimeError("AnyTLS server data mismatch")
                origin.wait()
                stdout, stderr = process.communicate(timeout=5)
                if process.returncode:
                    raise RuntimeError(f"AnyTLS server failed: {process.returncode} {stdout!r} {stderr!r}")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--pool-fixture", type=pathlib.Path)
    args = parser.parse_args()
    fixture = args.fixture.resolve()
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], capture_output=True, text=True, check=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
    with tempfile.TemporaryDirectory(prefix="nexus-anytls-network-") as directory:
        root = pathlib.Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key", "-out", root / "cert",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root / "password").write_text("anytls-network-secret\n")
        for name in ("key", "password"):
            (root / name).chmod(0o600)
        for backend in (0, 1):
            client_fixture(fixture, root, backend, args.pool_fixture.resolve() if args.pool_fixture else None)
            server_fixture(fixture, root, backend)
            print(f"AnyTLS actual TLS, fixed sing-box both directions, three reused streams and full FIN passed: backend={backend}", flush=True)


if __name__ == "__main__":
    main()
