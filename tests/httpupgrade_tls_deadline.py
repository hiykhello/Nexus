#!/usr/bin/env python3
"""Retain the original TLS/Upgrade deadline through blocked relay directions."""
import argparse
import concurrent.futures
import pathlib
import socket
import subprocess
import tempfile
import time

from httpupgrade_tls_network import (PATH, PAYLOAD, RESPONSE, WireTLS, certificates,
                                     client_context, exact, fixture_server, header,
                                     server_context, vless)


def completed(process, began, relay_began, stage):
    stdout, stderr = process.communicate(timeout=13)
    elapsed, relay_elapsed = time.monotonic() - began, time.monotonic() - relay_began
    if process.returncode != 1 or stage not in stderr or not 11.5 <= elapsed <= 13.3 or not 8.5 <= relay_elapsed <= 10.9:
        raise RuntimeError(f"HTTPUpgrade shared deadline: exit={process.returncode}, total={elapsed:.3f}s, "
                           f"relay={relay_elapsed:.3f}s, stdout={stdout!r}, stderr={stderr!r}")
    return elapsed, relay_elapsed


def client(binary, root, backend):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        began = time.monotonic()
        process = subprocess.Popen([binary, "client", str(listener.getsockname()[1]), "9", root / "cert", "localhost", str(backend)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with listener.accept()[0] as raw:
                raw.settimeout(14)
                peer = WireTLS(raw, server_context(root, ["http/1.1"]), True)
                if not header(peer).startswith(f"GET {PATH} HTTP/1.1\r\n".encode()):
                    raise RuntimeError("deadline client did not send Upgrade request")
                time.sleep(2)
                peer.write(RESPONSE + b"\x00\x00")
                if exact(peer, len(vless(9)) + len(PAYLOAD)) != vless(9) + PAYLOAD or peer.read(1):
                    raise RuntimeError("deadline client request/payload or authenticated half-close mismatch")
                relay_began = time.monotonic()
                result = completed(process, began, relay_began, b"response read")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
    print(f"HTTPUpgrade original deadline retained through client response read: backend={backend}, total={result[0]:.3f}s, "
          f"after-payload={result[1]:.3f}s", flush=True)


def server(binary, root, backend):
    with socket.socket() as target, fixture_server(binary, root, backend) as (process, remote):
        target.bind(("127.0.0.1", 0))
        target.listen(1)
        target.settimeout(5)
        began = time.monotonic()
        with socket.create_connection(("127.0.0.1", remote), timeout=5) as raw:
            raw.settimeout(14)
            peer = WireTLS(raw, client_context(root, ["http/1.1"]), False)
            time.sleep(2)
            request = f"GET {PATH} HTTP/1.1\r\nHost: cover.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".encode()
            peer.write(request + vless(target.getsockname()[1]))
            if not header(peer).startswith(b"HTTP/1.1 101 ") or exact(peer, 2) != b"\x00\x00":
                raise RuntimeError("deadline server did not finish Upgrade/VLESS target dial")
            with target.accept()[0] as connected:
                connected.settimeout(1)
                relay_began = time.monotonic()
                result = completed(process, began, relay_began, b"relay")
                if connected.recv(1):
                    raise RuntimeError("deadline server left target direction open or wrote unrequested data")
    print(f"HTTPUpgrade original deadline retained through both blocked server relay directions: backend={backend}, "
          f"total={result[0]:.3f}s, after-dial={result[1]:.3f}s", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--epoll-only", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nexus-httpupgrade-deadline-") as directory:
        root = pathlib.Path(directory)
        certificates(root)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            pending = [executor.submit(role, args.fixture.resolve(), root, backend)
                       for backend in ((0,) if args.epoll_only else (0, 1)) for role in (client, server)]
            for checked in pending:
                checked.result()


if __name__ == "__main__":
    main()
