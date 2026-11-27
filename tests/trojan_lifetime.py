#!/usr/bin/env python3
"""Trojan shared deadlines, bounded UDP queue recovery and pending stop."""
import argparse
import hashlib
import pathlib
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

from detour_network import Dns, exact, reserve, running


def address(host, port):
    raw = host.encode()
    return b"\x03" + bytes([len(raw)]) + raw + struct.pack("!H", port)


def reply(client):
    family = exact(client, 1)[0]
    if family not in (1, 4):
        raise RuntimeError("non-numeric reply")
    exact(client, 4 if family == 1 else 16)
    exact(client, 2)
    length = int.from_bytes(exact(client, 2), "big")
    if exact(client, 2) != b"\r\n":
        raise RuntimeError("reply delimiter")
    return exact(client, length)


def wait_for(predicate):
    limit = time.monotonic() + 3
    while not predicate():
        if time.monotonic() >= limit:
            raise RuntimeError("operation did not reach pending state")
        time.sleep(.01)


def queue(binary, root, workers, large=False, stop=False):
    dns = Dns(delay=5 if stop else .7)
    errors, received = [], []
    payloads = [bytes([index]) * (60000 if large else 128) for index in range(20 if large else 100)]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin:
        origin.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        origin.bind(("127.0.0.1", 0))
        origin.settimeout(5)
        port, config = reserve(), root / "queue.kdl"
        config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbound "trojan" type="trojan" {{ listen host="127.0.0.1" port={port};
 authentication {{ user "tester" password-file="{root / 'password'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
}}
outbound "direct" type="direct"
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.port}; strategy "ipv4_only"; }}
routing {{ final "direct"; }}
''')

        def echo():
            try:
                while len(received) < len(payloads):
                    data, peer = origin.recvfrom(65535)
                    received.append((data, peer))
                for data, peer in received:
                    origin.sendto(data, peer)
                    time.sleep(.01)
            except Exception as error:
                errors.append(error)

        thread = None
        try:
            with running([binary, "run", "--config", config], port, root / "queue.log") as process:
                context = ssl.create_default_context(cafile=str(root / "cert"))
                with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, \
                     context.wrap_socket(raw, server_hostname="localhost") as client:
                    request = hashlib.sha224(b"trojan-lifetime-secret").hexdigest().encode() + b"\r\n\x03\x01" + bytes(6) + b"\r\n"
                    client.sendall(request)
                    frames = b"".join(address("queue.test", origin.getsockname()[1]) + struct.pack("!H", len(data)) + b"\r\n" + data for data in payloads)
                    client.sendall(frames)
                    wait_for(lambda: "queue.test" in dns.names)
                    if stop:
                        started = time.monotonic()
                        process.terminate()
                        process.wait(timeout=2)
                        if time.monotonic() - started >= 1.8:
                            raise RuntimeError("saturated UDP association did not stop promptly")
                    else:
                        thread = threading.Thread(target=echo)
                        thread.start()
                        if [reply(client) for _ in payloads] != payloads:
                            raise RuntimeError("queued reply order or payload")
                if thread:
                    thread.join(6)
                    if thread.is_alive() or errors or [data for data, _ in received] != payloads:
                        raise RuntimeError(f"queued origin packets: count={len(received)} errors={errors}")
            print(f"Trojan {'byte' if large else 'count'} queue {'pending stop' if stop else 'recovery'}: workers={workers}", flush=True)
        finally:
            dns.close()
            if thread:
                thread.join(6)


def deadline(binary, root, workers, stop):
    dns = Dns(delay=.23)
    errors, accepted = [], threading.Event()
    with socket.socket() as stalled:
        stalled.bind(("127.0.0.1", 0))
        stalled.listen(2)
        stalled.settimeout(3)
        port, config = reserve(), root / "deadline.kdl"
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "remote" type="trojan" {{ server host="node.test" port={stalled.getsockname()[1]};
 authentication {{ password-file "{root / 'password'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
 bootstrap-resolver "boot"; connect-timeout-ms {5000 if stop else 800};
}}
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.port}; strategy "ipv4_only"; }}
routing {{ final "remote"; }}
''')

        def peer():
            try:
                with stalled.accept()[0] as conn:
                    conn.settimeout(3)
                    if exact(conn, 1) != b"\x16":
                        raise RuntimeError("missing ClientHello")
                    accepted.set()
                    while conn.recv(65535):
                        pass
            except ConnectionResetError:
                pass
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=peer)
        thread.start()
        try:
            with running([binary, "run", "--config", config], port, root / "deadline.log") as process:
                with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                    client.sendall(b"\x05\x01\x00")
                    if exact(client, 2) != b"\x05\x00":
                        raise RuntimeError("SOCKS greeting")
                    started = time.monotonic()
                    client.sendall(b"\x05\x01\x00" + address("target.test", 1234))
                    if not accepted.wait(2):
                        raise RuntimeError(f"TLS node not reached: {errors}")
                    if stop:
                        process.terminate()
                        process.wait(timeout=2)
                        if client.recv(1):
                            raise RuntimeError("pending TLS survived stop")
                    else:
                        result = exact(client, 10)
                        elapsed = time.monotonic() - started
                        if result[1] != 6 or not .65 <= elapsed < 1.25:
                            raise RuntimeError(f"target/node DNS and TLS did not share deadline: {result!r}, {elapsed:.3f}s")
            thread.join(4)
            if thread.is_alive() or errors or dns.names != {"target.test", "node.test"}:
                raise RuntimeError(f"TLS/DNS drain: {errors}, {dns.names}")
            print(f"Trojan target/node DNS and TLS {'stop' if stop else 'shared deadline'}: workers={workers}", flush=True)
        finally:
            dns.close()
            thread.join(4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="nexus-trojan-lifetime-") as directory:
        root = pathlib.Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key", "-out", root / "cert",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in ("key", "password"):
            if name == "password":
                (root / name).write_text("trojan-lifetime-secret\n")
            (root / name).chmod(0o600)
        for workers in (1, 2):
            for stop in (False, True):
                deadline(binary, root, workers, stop)
            queue(binary, root, workers)
            queue(binary, root, workers, large=True)
            queue(binary, root, workers, large=True, stop=True)


if __name__ == "__main__":
    main()
