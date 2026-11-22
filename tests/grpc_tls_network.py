#!/usr/bin/env python3
"""gRPC TLS h2, certificate identity and independent ALPN rejection probes."""
import argparse
import contextlib
import pathlib
import select
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading

from grpc_network import REVISION, UUID, SERVICE, PAYLOAD, box, exact, free_port, origin


@contextlib.contextmanager
def fixture_server(binary, root, backend, lite):
    process = subprocess.Popen([binary, "server", "0", root / "cert", root / "key", str(backend), str(int(lite))],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if not select.select([process.stdout], [], [], 6)[0]:
            raise RuntimeError("TLS fixture listener did not start")
        line = process.stdout.readline()
        if not line or not line.strip().isdigit():
            raise RuntimeError(f"TLS fixture exited: {process.communicate(timeout=5)!r}")
        yield process, int(line)
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=5)


def server_config(root, port):
    return {"log": {"level": "warn"}, "inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": port,
            "users": [{"uuid": UUID}], "transport": {"type": "grpc", "service_name": SERVICE},
            "tls": {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key"), "alpn": ["h2"]}}],
            "outbounds": [{"type": "direct"}]}


def client_config(root, port, remote, ca="cert", name="localhost"):
    return {"log": {"level": "warn"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": remote, "uuid": UUID,
            "transport": {"type": "grpc", "service_name": SERVICE},
            "tls": {"enabled": True, "server_name": name, "certificate_path": str(root / ca), "alpn": ["h2"]}}]}


def socks_request(sock, target):
    sock.sendall(b"\x05\x01\x00")
    if exact(sock, 2) != b"\x05\x00":
        raise RuntimeError("TLS SOCKS greeting")
    sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target))
    return exact(sock, 4)


def run_client(binary, root, backend, lite, remote, target, ca="cert", name="localhost", strict=False):
    return subprocess.run([binary, "client", str(remote), str(target), root / ca, name, str(backend), str(int(lite and not strict))],
                          capture_output=True, timeout=15)


def client_role(binary, peer, root, backend, lite, strict=False):
    with origin() as target:
        port = free_port()
        with box(peer, root, server_config(root, port), port):
            result = run_client(binary, root, backend, lite, port, target, strict=strict)
            if strict:
                if result.returncode != 1 or b"error=4" not in result.stderr:
                    raise RuntimeError(f"TLS standard accepted missing grpc-status: {result.returncode}, {result.stderr!r}")
            elif result.returncode:
                raise RuntimeError(f"TLS gRPC client lite={lite}, backend={backend}: {result.returncode}, {result.stderr!r}")


def server_role(binary, peer, root, backend, lite):
    with fixture_server(binary, root, backend, lite) as (server, remote), origin(not lite) as target:
        port = free_port()
        with box(peer, root, client_config(root, port, remote), port), socket.create_connection(("127.0.0.1", port), timeout=12) as client:
            reply = socks_request(client, target)
            if reply[1] or reply[3] not in (1, 4):
                raise RuntimeError(f"TLS SOCKS connect: {reply!r}")
            exact(client, 6 if reply[3] == 1 else 18)
            client.sendall(PAYLOAD)
            if not lite:
                client.shutdown(socket.SHUT_WR)
            if exact(client, len(PAYLOAD)) != PAYLOAD or client.recv(1):
                raise RuntimeError("TLS server payload/EOF mismatch")
        _, stderr = server.communicate(timeout=5)
        if server.returncode:
            raise RuntimeError(f"TLS gRPC server lite={lite}, backend={backend}: {server.returncode}, {stderr!r}")


@contextlib.contextmanager
def untouched_target():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        yield listener.getsockname()[1]
        if select.select([listener], [], [], 0)[0]:
            raise RuntimeError("unverified TLS peer reached the business target")


def client_identity(binary, peer, root, backend, lite):
    for ca, name in (("cert", "wrong.example"), ("untrusted-cert", "localhost")):
        with untouched_target() as target:
            port = free_port()
            with box(peer, root, server_config(root, port), port):
                result = run_client(binary, root, backend, lite, port, target, ca, name)
                if result.returncode != 1 or b"TLS client handshake" not in result.stderr or b"tls-error=2" not in result.stderr:
                    raise RuntimeError(f"client TLS identity was not rejected before gRPC: {result.returncode}, {result.stderr!r}")


def server_identity(binary, peer, root, backend, lite):
    for ca, name in (("cert", "wrong.example"), ("untrusted-cert", "localhost")):
        with fixture_server(binary, root, backend, lite) as (server, remote), untouched_target() as target:
            port = free_port()
            with box(peer, root, client_config(root, port, remote, ca, name), port):
                with socket.create_connection(("127.0.0.1", port), timeout=8) as client:
                    # grpc-go retries a failed transport in the background;
                    # its pending SOCKS request need not fail synchronously.
                    client.settimeout(.5)
                    try:
                        reply = socks_request(client, target)
                        if not reply[1]:
                            # The lite transport starts lazily, so SOCKS may
                            # acknowledge before its TLS attempt completes.
                            exact(client, 6 if reply[3] == 1 else 18)
                            client.sendall(b"unverified-probe")
                            if client.recv(1):
                                raise RuntimeError("unverified TLS identity returned business bytes")
                    except (TimeoutError, ConnectionResetError, RuntimeError) as error:
                        if isinstance(error, RuntimeError) and not str(error).startswith("unexpected EOF"):
                            raise
                _, stderr = server.communicate(timeout=5)
                if server.returncode != 1 or b"TLS server handshake" not in stderr:
                    raise RuntimeError(f"server TLS identity failure reached gRPC: {server.returncode}, {stderr!r}")


def client_alpn(binary, root, backend):
    for protocols in ([], ["http/1.1"]):
        received, errors, completed = [], [], []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.num_tickets = 0
        context.load_cert_chain(root / "cert", root / "key")
        context.set_alpn_protocols(protocols)
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
            result = run_client(binary, root, backend, False, listener.getsockname()[1], 9)
            worker.join(6)
            if worker.is_alive() or errors or completed != [None] or received != [b""] or result.returncode != 1 or b"TLS h2 ALPN" not in result.stderr:
                raise RuntimeError(f"client no-h2 rejection: protocols={protocols}, tls={completed}, bytes={received}, errors={errors}, fixture={result.stderr!r}")


def server_alpn(binary, root, backend):
    for protocols in ([], ["http/1.1"]):
        with fixture_server(binary, root, backend, False) as (server, remote):
            context = ssl.create_default_context(cafile=root / "cert")
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(protocols)
            try:
                with socket.create_connection(("127.0.0.1", remote), timeout=5) as raw:
                    with context.wrap_socket(raw, server_hostname="localhost"):
                        raise RuntimeError("server completed TLS without required h2")
            except ssl.SSLError:
                pass
            _, stderr = server.communicate(timeout=5)
            if server.returncode != 1 or b"TLS server handshake" not in stderr:
                raise RuntimeError(f"server no-h2 rejection: {server.returncode}, {stderr!r}")


def certificates(root):
    for prefix in ("", "untrusted-"):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / (prefix + "key"),
                        "-out", root / (prefix + "cert"), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root / (prefix + "key")).chmod(0o600)


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
    with tempfile.TemporaryDirectory(prefix="nexus-grpc-tls-") as directory:
        root = pathlib.Path(directory)
        certificates(root)
        for backend in ((0,) if args.epoll_only else (0, 1)):
            for peer, lite in peers:
                client_role(binary, peer, root, backend, lite)
                server_role(binary, peer, root, backend, lite)
                client_identity(binary, peer, root, backend, lite)
                server_identity(binary, peer, root, backend, lite)
                print(f"gRPC TLS h2 fixed {'lite' if lite else 'standard'} peer, both roles, 512 KiB and identity rejection: backend={backend}", flush=True)
            client_role(binary, peers[1][0], root, backend, True, strict=True)
            client_alpn(binary, root, backend)
            server_alpn(binary, root, backend)
            print(f"gRPC TLS independent missing/wrong h2 probes and strict status passed: backend={backend}", flush=True)


if __name__ == "__main__":
    main()
