#!/usr/bin/env python3
"""Check Hysteria 2 SOCKS TCP against a loopback peer that waits for payload."""
import argparse
from pathlib import Path
import select
import socket
import subprocess
import tempfile

from detour_network import exact, reserve
from dns_rule_support import nexus_process


def peer_line(peer):
    if not select.select([peer.stdout], [], [], 6)[0]:
        raise RuntimeError("timed out waiting for the loopback peer")
    line = peer.stdout.readline().strip()
    if not line:
        raise RuntimeError(f"loopback peer exited with status {peer.poll()}")
    return line


def run_case(binary, peer_binary, root, lazy, payload):
    peer = subprocess.Popen(
        [peer_binary, root / "cert.pem", root / "key.pem"],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        port = int(peer_line(peer).rsplit(":", 1)[1])
        front = reserve()
        config = root / "nexus.kdl"
        option = "lazy-tcp-response #true;" if lazy else ""
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{
    server host="127.0.0.1" port={port}
    authentication {{ password-file "{root / 'password'}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert.pem'}"; verify #true; }}
    connect-timeout-ms 2000
    quic {{ {option} }}
}}
routing {{ final "edge"; }}
''')
        with nexus_process(str(binary), str(config)), socket.create_connection(("127.0.0.1", front), timeout=5) as client:
            client.sendall(b"\x05\x01\x00")
            if exact(client, 2) != b"\x05\x00":
                raise RuntimeError("SOCKS greeting rejected")
            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
            reply = exact(client, 10)
            if peer_line(peer) != "waiting for TCP payload":
                raise RuntimeError("peer did not receive TCPRequest")
            if not lazy:
                if reply[1] == 0:
                    raise RuntimeError("default mode reported SOCKS success before TCPResponse")
                return
            if reply[1] != 0:
                raise RuntimeError(f"SOCKS rejected the lazy connection: {reply!r}")
            if payload is not None:
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
            rejected = payload is None or payload.startswith(b"!")
            try:
                if rejected:
                    if client.recv(1):
                        raise RuntimeError("a rejected or expired TCPResponse delivered application data")
                elif exact(client, len(payload)) != payload or client.recv(1):
                    raise RuntimeError("payload or FIN mismatch")
            except ConnectionResetError:
                if not rejected:
                    raise
    finally:
        if peer.poll() is None:
            peer.terminate()
        try:
            peer.wait(timeout=5)
        except subprocess.TimeoutExpired:
            peer.kill()
            peer.wait()
        peer.stdout.close()


def run(binary, peer_binary):
    with tempfile.TemporaryDirectory(prefix="nexus-hy2-lazy-") as folder:
        root = Path(folder)
        password = root / "password"
        password.write_text("test-password\n")
        password.chmod(0o600)
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-noenc", "-keyout", root / "key.pem", "-out", root / "cert.pem", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost", "-days", "1",
        ], check=True, capture_output=True)
        run_case(binary, peer_binary, root, False, b"")
        run_case(binary, peer_binary, root, True, b"lazy-first-payload")
        run_case(binary, peer_binary, root, True, b"!reject")
        run_case(binary, peer_binary, root, True, None)
        print("Hy2 default waits for TCPResponse; lazy mode passed first payload, FIN, rejection and deadline")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("peer", type=Path)
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.peer.resolve(strict=True))
