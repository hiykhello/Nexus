#!/usr/bin/env python3
"""Separate standard gRPC and fixed sing-box lite interoperability checks."""
import argparse
import contextlib
import json
import pathlib
import select
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

REVISION = "824dbcfb4dd0a95921840b1737b950cde590241e"
UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"
SERVICE = "nexus.Service"
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
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@contextlib.contextmanager
def box(binary, root, config, port):
    path, log = root / "box.json", root / "box.log"
    path.write_text(json.dumps(config))
    with log.open("wb") as output:
        process = subprocess.Popen([binary, "run", "-c", path], stdout=output, stderr=subprocess.STDOUT)
        try:
            limit = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"sing-box exited: {log.read_text()}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    if time.monotonic() >= limit:
                        raise
                    time.sleep(.02)
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            if process.returncode:
                raise RuntimeError(f"sing-box shutdown {process.returncode}: {log.read_text()}")


@contextlib.contextmanager
def origin(half_close=True):
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
                    client.settimeout(15)
                    time.sleep(.05)
                    data = bytearray(exact(client, len(PAYLOAD)))
                    if half_close and client.recv(1):
                        raise RuntimeError("origin received extra bytes")
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
            worker.join(18)
            if not failed and (worker.is_alive() or errors or received != [PAYLOAD]):
                raise RuntimeError(f"origin failed: errors={errors}, received={[len(data) for data in received]}")


@contextlib.contextmanager
def fixture_server(binary, backend, lite):
    process = subprocess.Popen([binary, "server", "0", str(backend), str(int(lite))], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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


def client_role(binary, peer, root, backend, lite, strict_reject=False):
    with origin() as target:
        port = free_port()
        config = {"log": {"level": "warn"}, "inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": port,
                  "users": [{"uuid": UUID}], "transport": {"type": "grpc", "service_name": SERVICE}}],
                  "outbounds": [{"type": "direct"}]}
        with box(peer, root, config, port):
            result = subprocess.run([binary, "client", str(port), str(target), str(backend), str(int(lite and not strict_reject))],
                                    capture_output=True, timeout=18)
            if strict_reject:
                if result.returncode != 1 or b"error=4" not in result.stderr:
                    raise RuntimeError(f"strict mode accepted lite without grpc-status: {result.returncode}, {result.stderr!r}")
            elif result.returncode:
                raise RuntimeError(f"gRPC client lite={lite}, backend={backend}: {result.returncode}, {result.stderr!r}")


def server_role(binary, peer, root, backend, lite):
    with fixture_server(binary, backend, lite) as (server, remote), origin(not lite) as target:
        port = free_port()
        config = {"log": {"level": "warn"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
                  "outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": remote, "uuid": UUID,
                                 "transport": {"type": "grpc", "service_name": SERVICE}}]}
        with box(peer, root, config, port), socket.create_connection(("127.0.0.1", port), timeout=15) as client:
            client.sendall(b"\x05\x01\x00")
            if exact(client, 2) != b"\x05\x00":
                raise RuntimeError("SOCKS greeting")
            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target))
            reply = exact(client, 4)
            if reply[1] or reply[3] not in (1, 4):
                raise RuntimeError(f"SOCKS connect: {reply!r}")
            exact(client, 6 if reply[3] == 1 else 18)
            client.sendall(PAYLOAD)
            if not lite:
                client.shutdown(socket.SHUT_WR)
            if exact(client, len(PAYLOAD)) != PAYLOAD or client.recv(1):
                raise RuntimeError("server relay payload/EOF mismatch")
        _, stderr = server.communicate(timeout=5)
        if server.returncode:
            raise RuntimeError(f"gRPC server lite={lite}, backend={backend}: {server.returncode}, {stderr!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--standard", type=pathlib.Path, required=True)
    parser.add_argument("--lite", type=pathlib.Path, default=shutil.which("sing-box"))
    parser.add_argument("--epoll-only", action="store_true")
    args = parser.parse_args()
    peers = ((args.standard.resolve(), False), (args.lite.resolve(), True))
    for peer, lite in peers:
        version = subprocess.run([peer, "version"], capture_output=True, text=True, check=True).stdout
        if f"Revision: {REVISION}" not in version or (("with_grpc" in version) == lite):
            raise RuntimeError(f"unexpected standard/lite peer: {version}")
    binary = args.fixture.resolve()
    with tempfile.TemporaryDirectory(prefix="nexus-grpc-network-") as directory:
        root = pathlib.Path(directory)
        for backend in ((0,) if args.epoll_only else (0, 1)):
            for peer, lite in peers:
                client_role(binary, peer, root, backend, lite)
                server_role(binary, peer, root, backend, lite)
                print(f"gRPC fixed {'lite' if lite else 'standard with_grpc'} peer, both roles, 512 KiB: backend={backend}", flush=True)
            client_role(binary, peers[1][0], root, backend, True, strict_reject=True)
            print(f"gRPC standard rejects lite missing grpc-status: backend={backend}", flush=True)


if __name__ == "__main__":
    main()
