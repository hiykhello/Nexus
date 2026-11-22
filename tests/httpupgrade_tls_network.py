#!/usr/bin/env python3
"""HTTPUpgrade TLS identity/ALPN and single-record pre-read interoperability."""
import argparse
import contextlib
import pathlib
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading

from grpc_network import REVISION, UUID, PAYLOAD, box, exact, free_port, origin
from grpc_tls_network import certificates, untouched_target

PATH = "/nexus-upgrade"
USER = bytes(range(16))
RESPONSE = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"


@contextlib.contextmanager
def fixture_server(binary, root, backend):
    process = subprocess.Popen([binary, "server", "0", root / "cert", root / "key", str(backend)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if not select.select([process.stdout], [], [], 6)[0]:
            raise RuntimeError("HTTPUpgrade TLS listener did not start")
        line = process.stdout.readline()
        if not line or not line.strip().isdigit():
            raise RuntimeError(f"HTTPUpgrade TLS fixture exited: {process.communicate(timeout=5)!r}")
        yield process, int(line)
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=5)


def transport():
    return {"type": "httpupgrade", "host": "cover.example", "path": PATH}


def server_config(root, port):
    return {"log": {"level": "warn"}, "inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": port,
            "users": [{"uuid": UUID}], "transport": transport(),
            "tls": {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key"), "alpn": ["http/1.1"]}}],
            "outbounds": [{"type": "direct"}]}


def client_config(root, port, remote, ca="cert", name="localhost"):
    return {"log": {"level": "warn"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": remote, "uuid": UUID, "transport": transport(),
            "tls": {"enabled": True, "server_name": name, "certificate_path": str(root / ca), "alpn": ["http/1.1"]}}]}


def socks_request(sock, target):
    sock.sendall(b"\x05\x01\x00")
    if exact(sock, 2) != b"\x05\x00":
        raise RuntimeError("HTTPUpgrade TLS SOCKS greeting")
    sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target))
    return exact(sock, 4)


def run_client(binary, root, backend, remote, target, ca="cert", name="localhost"):
    return subprocess.run([binary, "client", str(remote), str(target), root / ca, name, str(backend)], capture_output=True, timeout=15)


def prefetched(output):
    match = re.search(rb"prefetch=(\d+)", output)
    if not match or not int(match[1]):
        raise RuntimeError(f"expected retained Ready.unread prefix: {output!r}")


def client_role(binary, peer, root, backend):
    with origin() as target:
        port = free_port()
        with box(peer, root, server_config(root, port), port):
            result = run_client(binary, root, backend, port, target)
            if result.returncode:
                raise RuntimeError(f"HTTPUpgrade TLS client: {result.returncode}, {result.stderr!r}")


def server_role(binary, peer, root, backend):
    with fixture_server(binary, root, backend) as (server, remote), origin() as target:
        port = free_port()
        with box(peer, root, client_config(root, port, remote), port), socket.create_connection(("127.0.0.1", port), timeout=12) as client:
            reply = socks_request(client, target)
            if reply[1] or reply[3] not in (1, 4):
                raise RuntimeError(f"HTTPUpgrade TLS SOCKS connect: {reply!r}")
            exact(client, 6 if reply[3] == 1 else 18)
            client.sendall(PAYLOAD)
            client.shutdown(socket.SHUT_WR)
            if exact(client, len(PAYLOAD)) != PAYLOAD or client.recv(1):
                raise RuntimeError("HTTPUpgrade TLS server payload/EOF mismatch")
        _, stderr = server.communicate(timeout=5)
        if server.returncode:
            raise RuntimeError(f"HTTPUpgrade TLS server: {server.returncode}, {stderr!r}")


def identity(binary, peer, root, backend):
    for ca, name in (("cert", "wrong.example"), ("untrusted-cert", "localhost")):
        with untouched_target() as target:
            port = free_port()
            with box(peer, root, server_config(root, port), port):
                result = run_client(binary, root, backend, port, target, ca, name)
                if result.returncode != 1 or b"TLS client handshake" not in result.stderr or b"tls-error=2" not in result.stderr:
                    raise RuntimeError(f"HTTPUpgrade client identity failure: {result.returncode}, {result.stderr!r}")
        with fixture_server(binary, root, backend) as (server, remote), untouched_target() as target:
            port = free_port()
            with box(peer, root, client_config(root, port, remote, ca, name), port):
                with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                    client.settimeout(.5)
                    try:
                        reply = socks_request(client, target)
                        if not reply[1]:
                            exact(client, 6 if reply[3] == 1 else 18)
                            client.sendall(b"unverified-probe")
                            if client.recv(1):
                                raise RuntimeError("unverified HTTPUpgrade TLS peer returned business bytes")
                    except (TimeoutError, ConnectionResetError, RuntimeError) as error:
                        if isinstance(error, RuntimeError) and not str(error).startswith("unexpected EOF"):
                            raise
                _, stderr = server.communicate(timeout=5)
                if server.returncode != 1 or b"TLS server handshake" not in stderr:
                    raise RuntimeError(f"HTTPUpgrade server identity failure: {server.returncode}, {stderr!r}")


def server_context(root, protocols):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.num_tickets = 0
    context.load_cert_chain(root / "cert", root / "key")
    context.set_alpn_protocols(protocols)
    return context


def client_context(root, protocols):
    context = ssl.create_default_context(cafile=root / "cert")
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(protocols)
    return context


def alpn(binary, root, backend):
    for protocols in ([], ["h2"]):
        received, errors, completed = [], [], []
        context = server_context(root, protocols)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)

            def serve():
                try:
                    with listener.accept()[0] as raw:
                        raw.settimeout(5)
                        with context.wrap_socket(raw, server_side=True) as stream:
                            completed.append(stream.selected_alpn_protocol())
                            received.append(stream.recv(4096))
                except Exception as error:
                    errors.append(error)

            worker = threading.Thread(target=serve)
            worker.start()
            result = run_client(binary, root, backend, listener.getsockname()[1], 9)
            worker.join(6)
            if worker.is_alive() or errors or completed != [None] or received != [b""] or result.returncode != 1 or b"TLS http/1.1 ALPN" not in result.stderr:
                raise RuntimeError(f"HTTPUpgrade client required h1 boundary: {protocols}, {completed}, {received}, {errors}, {result.stderr!r}")
        with fixture_server(binary, root, backend) as (server, remote):
            try:
                with socket.create_connection(("127.0.0.1", remote), timeout=5) as raw:
                    with client_context(root, protocols).wrap_socket(raw, server_hostname="localhost"):
                        raise RuntimeError("HTTPUpgrade server accepted missing http/1.1")
            except ssl.SSLError:
                pass
            _, stderr = server.communicate(timeout=5)
            if server.returncode != 1 or b"TLS server handshake" not in stderr:
                raise RuntimeError(f"HTTPUpgrade server required h1 boundary: {server.returncode}, {stderr!r}")


class WireTLS:
    """Independent OpenSSL peer; retain/count the actual emitted TLS records."""
    def __init__(self, raw, context, server):
        self.raw, self.incoming, self.outgoing = raw, ssl.MemoryBIO(), ssl.MemoryBIO()
        self.stream = context.wrap_bio(self.incoming, self.outgoing, server_side=server, server_hostname=None if server else "localhost")
        self.call(self.stream.do_handshake)
        if self.stream.selected_alpn_protocol() != "http/1.1":
            raise RuntimeError("independent peer did not negotiate http/1.1")

    def flush(self):
        while self.outgoing.pending:
            self.raw.sendall(self.outgoing.read())

    def call(self, operation):
        while True:
            try:
                result = operation()
                self.flush()
                return result
            except ssl.SSLWantReadError:
                self.flush()
                wire = self.raw.recv(65536)
                if not wire:
                    raise RuntimeError("independent peer got unauthenticated TCP EOF")
                self.incoming.write(wire)
            except ssl.SSLWantWriteError:
                self.flush()
            except ssl.SSLZeroReturnError:
                self.flush()
                return b""

    def read(self, size):
        return self.call(lambda: self.stream.read(size))

    def recv(self, size):
        return self.read(size)

    def write(self, data, one_record=False):
        if one_record:
            if self.stream.write(data) != len(data):
                raise RuntimeError("independent peer short TLS write")
            wire = self.outgoing.read()
            records, offset = 0, 0
            while offset < len(wire):
                if len(wire) - offset < 5 or wire[offset] != 23:
                    raise RuntimeError("single-record probe included a control/plaintext record")
                size = struct.unpack("!H", wire[offset + 3:offset + 5])[0]
                offset += 5 + size
                records += 1
            if records != 1 or offset != len(wire):
                raise RuntimeError(f"probe did not occupy exactly one TLS record: {records}, {offset}, {len(wire)}")
            self.raw.sendall(wire)
        else:
            for offset in range(0, len(data), 16384):
                part = data[offset:offset + 16384]
                if self.call(lambda: self.stream.write(part)) != len(part):
                    raise RuntimeError("short independent TLS body write")

    def close_write(self):
        try:
            self.stream.unwrap()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        self.flush()


def header(stream):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        data.extend(exact(stream, 1))
        if len(data) > 16384:
            raise RuntimeError("independent peer received oversized HTTP header")
    return bytes(data)


def vless(target):
    return b"\x00" + USER + b"\x00\x01" + struct.pack("!H", target) + b"\x01\x7f\x00\x00\x01"


def coalesced_client(binary, root, backend):
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)

        def serve():
            try:
                with listener.accept()[0] as raw:
                    raw.settimeout(12)
                    peer = WireTLS(raw, server_context(root, ["http/1.1"]), True)
                    request = header(peer)
                    if not request.startswith(f"GET {PATH} HTTP/1.1\r\n".encode()):
                        raise RuntimeError("unexpected Upgrade GET")
                    peer.write(RESPONSE + b"\x00\x00" + PAYLOAD[:8192], one_record=True)
                    if exact(peer, len(vless(9)) + len(PAYLOAD)) != vless(9) + PAYLOAD or peer.read(1):
                        raise RuntimeError("coalesced client lost request bytes or half-close")
                    peer.write(PAYLOAD[8192:])
                    peer.close_write()
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        result = run_client(binary, root, backend, listener.getsockname()[1], 9)
        worker.join(15)
        if worker.is_alive() or errors or result.returncode:
            raise RuntimeError(f"single-record 101/VLESS/data client: {errors}, {result.returncode}, {result.stderr!r}")
        prefetched(result.stdout)


def coalesced_server(binary, root, backend):
    with fixture_server(binary, root, backend) as (server, remote), origin() as target:
        with socket.create_connection(("127.0.0.1", remote), timeout=12) as raw:
            peer = WireTLS(raw, client_context(root, ["h2", "http/1.1"]), False)
            request = f"GET {PATH}?ignored=1 HTTP/1.1\r\nHost: cover.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".encode()
            peer.write(request + vless(target) + PAYLOAD[:8192], one_record=True)
            peer.write(PAYLOAD[8192:])
            peer.close_write()
            if not header(peer).startswith(b"HTTP/1.1 101 ") or exact(peer, 2) != b"\x00\x00":
                raise RuntimeError("coalesced server Upgrade/VLESS response")
            if exact(peer, len(PAYLOAD)) != PAYLOAD or peer.read(1):
                raise RuntimeError("coalesced server lost Ready/TLS suffix or half-close")
        stdout, stderr = server.communicate(timeout=5)
        if server.returncode:
            raise RuntimeError(f"single-record GET/VLESS/data server: {server.returncode}, {stderr!r}")
        prefetched(stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--peer", type=pathlib.Path, default=shutil.which("sing-box"))
    parser.add_argument("--epoll-only", action="store_true")
    args = parser.parse_args()
    peer = args.peer.resolve()
    if f"Revision: {REVISION}" not in subprocess.run([peer, "version"], capture_output=True, text=True, check=True).stdout:
        raise RuntimeError("unexpected fixed HTTPUpgrade peer")
    binary = args.fixture.resolve()
    with tempfile.TemporaryDirectory(prefix="nexus-httpupgrade-tls-") as directory:
        root = pathlib.Path(directory)
        certificates(root)
        for backend in ((0,) if args.epoll_only else (0, 1)):
            client_role(binary, peer, root, backend)
            server_role(binary, peer, root, backend)
            identity(binary, peer, root, backend)
            alpn(binary, root, backend)
            coalesced_client(binary, root, backend)
            coalesced_server(binary, root, backend)
            print(f"HTTPUpgrade TLS fixed peer both roles, identity/required h1 ALPN and exact one-record pre-read passed: backend={backend}", flush=True)


if __name__ == "__main__":
    main()
