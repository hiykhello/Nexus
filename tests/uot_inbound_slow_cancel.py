#!/usr/bin/env python3
"""Saturate a real downstream TCP socket and cancel the inbound association."""
import base64
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

server_binary = pathlib.Path(sys.argv[1]).resolve()
fixture = server_binary.with_name("nexus-proxy-uot-fixture")
with tempfile.TemporaryDirectory(prefix="nexus-uot-slow-") as directory, socket.socket() as downstream:
    root = pathlib.Path(directory)
    (root / "key").write_text(base64.b64encode(bytes(range(16))).decode())
    (root / "key").chmod(0o600)
    downstream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    downstream.bind(("127.0.0.1", 0)); downstream.listen(5); downstream.settimeout(5)
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
    (root / "server.kdl").write_text(f'''schema-version 1
role "server"
workers 2
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={downstream.getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
routing {{ default-outbound "edge"; }}
''')
    server = subprocess.Popen([server_binary, "run", "--config", root / "server.kdl"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=dict(os.environ, NEXUS_TEST_UOT_QUEUE_TRACE="1"))
    client = peer = None
    try:
        deadline = time.monotonic() + 5
        while True:
            if server.poll() is not None: raise RuntimeError(f"server exited: {server.stderr.read()!r}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2): break
            except OSError:
                if time.monotonic() >= deadline: raise
                time.sleep(.02)
        for iteration in range(3):
            client = subprocess.Popen([fixture, str(port), "53", "0", "slow"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            peer, _ = downstream.accept()
            if not select.select([server.stderr], [], [], 10)[0]: raise RuntimeError(f"{iteration}: no queue saturation")
            trace = server.stderr.readline().split()
            if len(trace) != 6 or trace[:3] != [b"uot", b"queue", b"full"]:
                raise RuntimeError(f"{iteration}: unexpected trace {trace!r}")
            count, queued, waiting = map(int, trace[3:])
            if count >= 64 or queued + waiting <= 1024 * 1024:
                raise RuntimeError(f"{iteration}: byte limit not reached: {trace!r}")
            time.sleep(.3)
            connections = subprocess.check_output(["ss", "-tn", "dst", f"127.0.0.1:{downstream.getsockname()[1]}"], text=True).splitlines()[1:]
            if not connections or not any(int(line.split()[2]) > 0 for line in connections):
                raise RuntimeError(f"{iteration}: no pending downstream TCP send queue: {connections!r}")
            if iteration < 2:
                client.terminate(); client.communicate(timeout=5); client = None
            else:
                server.terminate(); _, stderr = server.communicate(timeout=5)
                if server.returncode: raise RuntimeError(f"shutdown: {stderr!r}")
                server = None
                client.communicate(timeout=5); client = None
            # Once cancellation is initiated, drain the kernel receive queue and observe EOF.
            peer.settimeout(10)
            received = 0
            while True:
                data = peer.recv(65536)
                if not data: break
                received += len(data)
            if not received: raise RuntimeError(f"{iteration}: downstream received no encrypted data")
            peer.close(); peer = None
        print("UoT inbound real downstream backpressure: queue byte limit, cancellation, reuse and active shutdown passed")
    finally:
        if peer: peer.close()
        if client and client.poll() is None: client.kill(); client.communicate(timeout=5)
        if server and server.poll() is None: server.terminate(); server.communicate(timeout=5)
