#!/usr/bin/env python3
"""Check benchmark fixture startup, SOCKS forwarding and orderly shutdown.

This does not measure performance. With --udp it also sends real datagrams
through both SS UDP listeners using the project's fixed sing-box version.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import time


def exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise RuntimeError("unexpected EOF")
        result.extend(part)
    return bytes(result)


def line(process: subprocess.Popen[str]) -> list[str]:
    assert process.stdout is not None
    if not select.select([process.stdout], [], [], 10)[0]:
        raise RuntimeError("fixture did not respond")
    value = process.stdout.readline()
    if not value:
        raise RuntimeError("fixture exited before responding")
    return value.split()


def forward(port: int) -> None:
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(5)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(b"\x05\x01\x00")
            if exact(client, 2) != b"\x05\x00":
                raise RuntimeError("SOCKS greeting failed")
            destination = socket.inet_aton("127.0.0.1") + struct.pack("!H", origin.getsockname()[1])
            client.sendall(b"\x05\x01\x00\x01" + destination)
            if exact(client, 10)[:3] != b"\x05\x00\x00":
                raise RuntimeError("SOCKS connect failed")
            with origin.accept()[0] as peer:
                peer.settimeout(5)
                client.sendall(b"ping")
                if exact(peer, 4) != b"ping":
                    raise RuntimeError("origin received wrong bytes")
                peer.sendall(b"pong")
                if exact(client, 4) != b"pong":
                    raise RuntimeError("client received wrong bytes")


def forward_udp(ports: list[int]) -> None:
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    version = subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True)
    if f"Revision: {revision}" not in version.stdout:
        raise RuntimeError("unexpected sing-box revision")
    with tempfile.TemporaryDirectory(prefix="nexus-bench-udp-smoke-") as directory:
        for index, port in enumerate(ports):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                socks_port = reservation.getsockname()[1]
            config = {"log": {"level": "warn"},
                      "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
                      "outbounds": [{"type": "shadowsocks", "tag": "edge", "server": "127.0.0.1",
                                     "server_port": port, "method": "2022-blake3-aes-128-gcm",
                                     "password": base64.b64encode(bytes(range(index * 16, (index + 1) * 16))).decode()}],
                      "route": {"final": "edge"}}
            path = Path(directory) / f"client-{index}.json"
            path.write_text(json.dumps(config))
            subprocess.run(["sing-box", "check", "-c", str(path)], check=True, capture_output=True)
            with tempfile.TemporaryFile(mode="w+") as errors:
                box = subprocess.Popen(["sing-box", "run", "-c", str(path)],
                                       stdout=subprocess.DEVNULL, stderr=errors)
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            tcp = socket.create_connection(("127.0.0.1", socks_port), timeout=.2)
                            break
                        except OSError:
                            if box.poll() is not None or time.monotonic() >= deadline:
                                errors.seek(0)
                                raise RuntimeError(f"sing-box did not start: {errors.read()}")
                            time.sleep(.02)
                    with tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, \
                            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin:
                        tcp.settimeout(5)
                        udp.bind(("127.0.0.1", 0))
                        udp.settimeout(5)
                        origin.bind(("127.0.0.1", 0))
                        origin.settimeout(5)
                        tcp.sendall(b"\x05\x01\x00")
                        if exact(tcp, 2) != b"\x05\x00":
                            raise RuntimeError("UDP association greeting failed")
                        tcp.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.getsockname()[1]))
                        if exact(tcp, 4) != b"\x05\x00\x00\x01":
                            raise RuntimeError("UDP association failed")
                        endpoint = ("127.0.0.1", struct.unpack("!H", exact(tcp, 6)[4:])[0])
                        address = b"\x7f\x00\x00\x01" + struct.pack("!H", origin.getsockname()[1])
                        udp.sendto(b"\x00\x00\x00\x01" + address + b"ping", endpoint)
                        payload, peer = origin.recvfrom(65535)
                        if payload != b"ping":
                            raise RuntimeError("UDP origin received wrong bytes")
                        origin.sendto(b"pong", peer)
                        reply, _ = udp.recvfrom(65535)
                        if reply != b"\x00\x00\x00\x01" + address + b"pong":
                            raise RuntimeError(f"UDP client received wrong reply: {reply!r}")
                finally:
                    if box.poll() is None:
                        box.terminate()
                    try:
                        box.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        box.kill()
                        box.wait()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--mode", choices=("per-worker", "shared", "snapshot", "group", "coordinator"), required=True)
    parser.add_argument("--multi", action="store_true", help="fixture also starts two SS UDP listeners")
    parser.add_argument("--udp", action="store_true", help="test both SS UDP listeners with sing-box")
    args = parser.parse_args()
    if args.udp and not args.multi:
        parser.error("--udp requires --multi")
    env = dict(os.environ)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        dns.bind(("127.0.0.1", 0))
        arguments = [str(args.fixture.resolve()), str(dns.getsockname()[1]), "2"]
        reservations: list[socket.socket] = []
        udp_ports: list[int] = []
        if args.multi:
            for _ in range(2):
                reserved = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                reserved.bind(("127.0.0.1", 0))
                reservations.append(reserved)
                udp_ports.append(reserved.getsockname()[1])
                arguments.append(str(udp_ports[-1]))
            for reserved in reservations:
                reserved.close()
        process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=env)
        try:
            ready = line(process)
            expected_len = 4 if args.multi else 3
            if len(ready) != expected_len or ready[0] != "ready" or ready[-1] != args.mode:
                raise RuntimeError(f"unexpected ready line: {ready}")
            ports = [int(value) for value in ready[1:-1]]
            for port in ports:
                forward(port)
            if args.udp:
                forward_udp(udp_ports)
            assert process.stdin is not None
            if not args.multi:
                process.stdin.write(f"restart {dns.getsockname()[1]}\n")
                process.stdin.flush()
                restarted = line(process)
                if len(restarted) != 4 or restarted[:3] != ["ready", str(ports[0]), args.mode]:
                    raise RuntimeError(f"unexpected restart line: {restarted}")
                forward(ports[0])
            process.stdin.write("stop\n")
            process.stdin.flush()
            stopped = line(process)
            if len(stopped) != 2 or stopped[0] != "stopped":
                raise RuntimeError(f"unexpected stop line: {stopped}")
            code = process.wait(timeout=10)
            if code:
                raise RuntimeError(f"fixture exited with status {code}")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            assert process.stderr is not None
            error = process.stderr.read()
            if error:
                print(error, end="")
    print(f"{args.fixture.name}: {args.mode} startup, SOCKS forwarding" +
          (", SS UDP" if args.udp else "") + " and shutdown passed")


if __name__ == "__main__":
    main()
