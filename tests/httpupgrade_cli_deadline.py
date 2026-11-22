#!/usr/bin/env python3
"""Production TLS/Upgrade/VLESS/DNS share the original startup deadline."""
import argparse
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from dns_rule_support import DnsPeer, connect, exact, free_port, nexus_process
from httpupgrade_cli_network import ALICE, HOST, PATH, TARGET, UUID, client_config, server_config, vless
from httpupgrade_tls_network import certificates, client_context, header, server_context


def incoming(binary, root, workers):
    with DnsPeer() as dns:
        dns.drop.update(("waiting.test", kind) for kind in (1, 28))
        front = free_port()
        config = server_config(root, front, workers, dns)
        text = config.read_text().replace('outbound "direct" type="direct"',
            'outbound "direct" type="direct" { connect-timeout-ms 20000; }')
        config.write_text(text)
        with nexus_process(binary, config), connect(front) as raw:
            started = time.monotonic()
            raw.settimeout(12)
            with client_context(root, ["http/1.1"]).wrap_socket(raw, server_hostname="localhost") as peer:
                peer.sendall(f"GET {TARGET} HTTP/1.1\r\nHost: {HOST}\r\nConnection: Upgrade\r\n".encode())
                time.sleep(2)
                peer.sendall(b"Upgrade: websocket\r\n\r\n")
                if not header(peer).startswith(b"HTTP/1.1 101 "):
                    raise RuntimeError("production Upgrade did not complete")
                peer.sendall(vless("waiting.test", 9))
                try:
                    output = peer.recv(1)
                except (ssl.SSLError, ConnectionResetError):
                    output = b""
                elapsed = time.monotonic() - started
                if output or not 9 <= elapsed <= 11.5:
                    raise RuntimeError(f"inbound reset its startup budget: {elapsed:.3f}s, output={output!r}")
                if not any(name == "waiting.test" for name, *_ in dns.seen):
                    raise RuntimeError("deadline case did not reach a real pending DNS query")
        print(f"HTTPUpgrade production inbound TLS/header/DNS original 10s deadline passed: workers={workers}, elapsed={elapsed:.3f}s", flush=True)


def outgoing(binary, root, workers):
    errors, observed = [], []
    with DnsPeer() as dns, socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        remote, front = listener.getsockname()[1], free_port()
        config = client_config(root, front, remote, workers, dns)
        config.write_text(config.read_text().replace('outbound "edge" type="vless" {',
            'outbound "edge" type="vless" { connect-timeout-ms 1200;'))

        def serve():
            try:
                with listener.accept()[0] as raw:
                    raw.settimeout(4)
                    with server_context(root, ["http/1.1"]).wrap_socket(raw, server_side=True) as peer:
                        wire = header(peer)
                        if not wire.startswith(f"GET {TARGET} HTTP/1.1\r\n".encode()):
                            raise RuntimeError("deadline peer did not receive a real Upgrade")
                        time.sleep(.4)
                        peer.sendall(b"HTTP/1.1 101 Switching Protocols\r\n")
                        # A partial 101 must not authorize any VLESS or UUID.
                        try:
                            observed.append(peer.recv(1))
                        except (ssl.SSLError, ConnectionResetError):
                            observed.append(b"")
            except Exception as error:
                errors.append(error)

        with nexus_process(binary, config):
            thread = threading.Thread(target=serve)
            thread.start()
            try:
                with connect(front) as client:
                    client.settimeout(4)
                    client.sendall(b"\x05\x01\x00")
                    if exact(client, 2) != b"\x05\x00":
                        raise RuntimeError("deadline SOCKS greeting")
                    started = time.monotonic()
                    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x09")
                    reply = exact(client, 4)
                    elapsed = time.monotonic() - started
                    if reply[1] != 6 or not .9 <= elapsed <= 2:
                        raise RuntimeError(f"outbound Upgrade lost connect deadline: reply={reply!r}, elapsed={elapsed:.3f}s")
            finally:
                thread.join(5)
            if thread.is_alive() or errors or observed != [b""]:
                raise RuntimeError(f"pending Upgrade did not drain or sent VLESS early: {errors!r}, {observed!r}")
        print(f"HTTPUpgrade production outbound TLS/partial-101 original 1200ms deadline passed: workers={workers}, elapsed={elapsed:.3f}s", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nexus-upgrade-cli-deadline-") as directory:
        root = pathlib.Path(directory)
        certificates(root)
        for name, value in (("uuid", UUID), ("alice", ALICE)):
            (root / name).write_text(value + "\n")
            (root / name).chmod(0o600)
        for workers in (1, 2):
            incoming(args.binary.resolve(), root, workers)
            outgoing(args.binary.resolve(), root, workers)


if __name__ == "__main__":
    main()
