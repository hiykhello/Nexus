#!/usr/bin/env python3
"""HTTPUpgrade byte-stream fixture against the fixed sing-box in both roles."""
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

REVISION = "824dbcfb4dd0a95921840b1737b950cde590241e"
UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"
USER = bytes(range(16))
PATH = "/nexus-upgrade"
PAYLOAD = bytes(range(256)) * 2048


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise RuntimeError(f"unexpected EOF after {len(result)}/{size} bytes")
        result.extend(part)
    return bytes(result)


def free_port():
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        return reserve.getsockname()[1]


def wait_port(process, port, log):
    limit = time.monotonic() + 5
    while True:
        if process.poll() is not None:
            raise RuntimeError(f"sing-box exited: {log.read_text()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            if time.monotonic() >= limit:
                raise
            time.sleep(.02)


@contextlib.contextmanager
def box(root, config, port):
    path, log = root / "box.json", root / "box.log"
    path.write_text(json.dumps(config))
    with log.open("wb") as output:
        process = subprocess.Popen(["sing-box", "run", "-c", path], stdout=output, stderr=subprocess.STDOUT)
        try:
            wait_port(process, port, log)
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            if process.returncode:
                raise RuntimeError(f"sing-box shutdown {process.returncode}: {log.read_text()}")


@contextlib.contextmanager
def origin():
    errors, received = [], []
    stopped = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(.1)

        def serve():
            try:
                while not stopped.is_set():
                    try:
                        client, _ = listener.accept()
                        break
                    except TimeoutError:
                        continue
                else:
                    return
                with client:
                    client.settimeout(12)
                    data = bytearray()
                    while part := client.recv(16384):
                        data.extend(part)
                    received.append(bytes(data))
                    time.sleep(.03)
                    client.sendall(data)
                    client.shutdown(socket.SHUT_WR)
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        failed = False
        try:
            yield listener.getsockname()[1]
        except BaseException:
            failed = True
            raise
        finally:
            stopped.set()
            worker.join(15)
            if not failed and (worker.is_alive() or errors):
                raise RuntimeError(f"origin failed: {errors}")
            if not failed and received != [PAYLOAD]:
                raise RuntimeError("origin payload mismatch")


@contextlib.contextmanager
def fixture_server(binary, backend):
    process = subprocess.Popen([binary, "server", "0", str(backend)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if not select.select([process.stdout], [], [], 6)[0]:
            raise RuntimeError("fixture listener did not start")
        line = process.stdout.readline()
        if not line or not line.strip().isdigit():
            raise RuntimeError(f"fixture exited: {process.communicate(timeout=5)!r}")
        yield process, int(line)
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=5)


def client_role(binary, root, backend):
    with origin() as target:
        port = free_port()
        config = {"log": {"level": "warn"}, "inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": port,
                  "users": [{"uuid": UUID}], "transport": {"type": "httpupgrade", "host": "cover.example", "path": PATH}}],
                  "outbounds": [{"type": "direct"}]}
        with box(root, config, port):
            result = subprocess.run([binary, "client", str(port), str(target), str(backend)], capture_output=True, timeout=18)
            if result.returncode:
                raise RuntimeError(f"HTTPUpgrade client {result.returncode}: {result.stderr!r}")


def server_role(binary, root, backend):
    with fixture_server(binary, backend) as (server, remote), origin() as target:
        port = free_port()
        config = {"log": {"level": "warn"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
                  "outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": remote, "uuid": UUID,
                                 "transport": {"type": "httpupgrade", "host": "cover.example", "path": PATH}}]}
        with box(root, config, port), socket.create_connection(("127.0.0.1", port), timeout=10) as client:
            client.sendall(b"\x05\x01\x00")
            if exact(client, 2) != b"\x05\x00":
                raise RuntimeError("SOCKS greeting")
            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target))
            reply = exact(client, 4)
            if reply[1] or reply[3] not in (1, 4):
                raise RuntimeError(f"SOCKS connect: {reply!r}")
            exact(client, 6 if reply[3] == 1 else 18)
            client.sendall(PAYLOAD)
            client.shutdown(socket.SHUT_WR)
            if exact(client, len(PAYLOAD)) != PAYLOAD or client.recv(1):
                raise RuntimeError("server relay payload or half-close")
        _, stderr = server.communicate(timeout=5)
        if server.returncode:
            raise RuntimeError(f"HTTPUpgrade server {server.returncode}: {stderr!r}")


def raw_server(binary, backend):
    with fixture_server(binary, backend) as (server, port), origin() as target:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as client:
            header = f"GET {PATH}?ignored=1 HTTP/1.1\r\nHost: cover.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUser-Agent: probe\r\n\r\n".encode()
            inner = b"\x00" + USER + b"\x00\x01" + struct.pack("!H", target) + b"\x01\x7f\x00\x00\x01"
            for offset in range(0, len(header) - 3, 3):
                client.sendall(header[offset:min(offset + 3, len(header) - 3)])
            client.sendall(header[-3:] + inner + PAYLOAD)
            client.shutdown(socket.SHUT_WR)
            response = bytearray()
            while b"\r\n\r\n" not in response:
                response.extend(exact(client, 1))
            if not response.startswith(b"HTTP/1.1 101 ") or exact(client, 2) != b"\x00\x00":
                raise RuntimeError("Upgrade or inner protocol response")
            if exact(client, len(PAYLOAD)) != PAYLOAD or client.recv(1):
                raise RuntimeError("prefetched inner header or payload lost")
        _, stderr = server.communicate(timeout=5)
        if server.returncode:
            raise RuntimeError(f"raw HTTPUpgrade server {server.returncode}: {stderr!r}")


def rejected_server(binary, backend):
    for method, target, extra in (("POST", PATH, ""), ("GET", PATH + "/wrong", ""),
                                  ("GET", PATH, "Host: duplicate.example\r\n"),
                                  ("GET", PATH, "Content-Length: 1\r\n"),
                                  ("GET", PATH, "Transfer-Encoding: chunked\r\n")):
        with fixture_server(binary, backend) as (server, port):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(f"{method} {target} HTTP/1.1\r\nHost: cover.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{extra}\r\n".encode())
                try:
                    received = client.recv(1)
                except ConnectionResetError:
                    received = b""
                if received:
                    raise RuntimeError("rejected handshake received success bytes")
            server.communicate(timeout=5)
            if server.returncode != 1:
                raise RuntimeError(f"rejected handshake exit {server.returncode}")


def rejected_client(binary, backend):
    for status, fields in (("200 OK", "Connection: Upgrade\r\nUpgrade: websocket\r\n"),
                           ("101 Switching Protocols", "Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n"),
                           ("101 Switching Protocols", "Connection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 1\r\n"),
                           ("101 Switching Protocols", "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: abc\r\n")):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            process = subprocess.Popen([binary, "client", str(listener.getsockname()[1]), "9", str(backend)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with listener.accept()[0] as client:
                    client.settimeout(5)
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        request.extend(exact(client, 1))
                    if not request.startswith(f"GET {PATH} HTTP/1.1\r\n".encode()):
                        raise RuntimeError("unexpected client request")
                    response = f"HTTP/1.1 {status}\r\n{fields}\r\n".encode()
                    for offset in range(0, len(response), 3):
                        client.sendall(response[offset:offset + 3])
                    try:
                        received = client.recv(1)
                    except ConnectionResetError:
                        received = b""
                    if received:
                        raise RuntimeError("client sent inner protocol after invalid response")
                _, stderr = process.communicate(timeout=5)
                if process.returncode != 1:
                    raise RuntimeError(f"invalid Upgrade response exit {process.returncode}: {stderr!r}")
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--epoll-only", action="store_true")
    args = parser.parse_args()
    if f"Revision: {REVISION}" not in subprocess.run(["sing-box", "version"], capture_output=True, text=True, check=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
    binary = args.fixture.resolve()
    with tempfile.TemporaryDirectory(prefix="nexus-httpupgrade-") as directory:
        root = pathlib.Path(directory)
        for backend in ((0,) if args.epoll_only else (0, 1)):
            client_role(binary, root, backend)
            server_role(binary, root, backend)
            raw_server(binary, backend)
            rejected_server(binary, backend)
            rejected_client(binary, backend)
            print(f"HTTPUpgrade fixed sing-box client/server, fragmented pre-read, 512 KiB half-close and rejection passed: backend={backend}", flush=True)


if __name__ == "__main__":
    main()
