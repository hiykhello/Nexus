#!/usr/bin/env python3
"""Resume a saturated TCP relay into a pinned sing-box UoT server."""
import base64
import json
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

nexus = pathlib.Path(sys.argv[1]).resolve()
fixture = nexus.with_name("nexus-proxy-uot-fixture")
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], capture_output=True, text=True, check=True).stdout:
    raise RuntimeError("unexpected sing-box revision")
def reserve_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); return sock.getsockname()[1]

with tempfile.TemporaryDirectory(prefix="nexus-uot-resume-") as directory, socket.socket() as relay, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin:
    root = pathlib.Path(directory); port = reserve_port(); box_port = reserve_port()
    relay.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    relay.bind(("127.0.0.1", 0)); relay.listen(1); relay.settimeout(10)
    origin.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    origin.bind(("127.0.0.1", 0)); origin.settimeout(.1)
    key = base64.b64encode(bytes(range(16))).decode()
    (root / "key").write_text(key); (root / "key").chmod(0o600)
    (root / "server.kdl").write_text(f'''schema-version 1
role "server"
workers 2
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={relay.getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
routing {{ final "edge"; }}
''')
    config = {"log":{"level":"error"}, "inbounds":[{"type":"shadowsocks", "listen":"127.0.0.1", "listen_port":box_port, "method":"2022-blake3-aes-128-gcm", "password":key}], "outbounds":[{"type":"direct", "tag":"direct"}], "route":{"final":"direct"}}
    (root / "box.json").write_text(json.dumps(config))
    subprocess.run(["sing-box", "check", "-c", root / "box.json"], capture_output=True, check=True)
    stop = threading.Event(); received = []; errors = []; threads = []
    def echo():
        try:
            while not stop.is_set():
                try: data, peer = origin.recvfrom(65535)
                except socket.timeout: continue
                received.append(data); origin.sendto(data, peer)
        except OSError as exc:
            if not stop.is_set(): errors.append(repr(exc))
    thread = threading.Thread(target=echo, daemon=True); thread.start(); threads.append(thread)
    server = box = client = peer = remote = None
    try:
        box = subprocess.Popen(["sing-box", "run", "-c", root / "box.json"], stderr=subprocess.PIPE)
        server = subprocess.Popen([nexus, "run", "--config", root / "server.kdl"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=dict(os.environ, NEXUS_TEST_UOT_QUEUE_TRACE="1"))
        deadline = time.monotonic() + 5
        while True:
            if server.poll() is not None: raise RuntimeError(f"server exited: {server.stderr.read()!r}")
            if box.poll() is not None: raise RuntimeError(f"sing-box exited: {box.stderr.read()!r}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2): break
            except OSError:
                if time.monotonic() >= deadline: raise
                time.sleep(.02)
        client = subprocess.Popen([fixture, str(port), str(origin.getsockname()[1]), "0", "test-resume"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        peer, _ = relay.accept()
        if not select.select([server.stderr], [], [], 10)[0]: raise RuntimeError("queue did not saturate")
        trace = server.stderr.readline().split()
        if len(trace) != 6 or trace[:3] != [b"uot", b"queue", b"full"] or int(trace[3]) != 64:
            raise RuntimeError(f"unexpected queue trace: {trace!r}")
        time.sleep(.3)
        connections = subprocess.check_output(["ss", "-tn", "dst", f"127.0.0.1:{relay.getsockname()[1]}"], text=True).splitlines()[1:]
        if not connections or not any(int(line.split()[2]) > 0 for line in connections): raise RuntimeError(f"no pending TCP sends: {connections!r}")
        remote = socket.create_connection(("127.0.0.1", box_port), timeout=5); remote.settimeout(None)
        def forward(source, dest, paced):
            try:
                while not stop.is_set():
                    data = source.recv(16384)
                    if not data: break
                    dest.sendall(data)
                    if paced: time.sleep(.003)
            except OSError as exc:
                if not stop.is_set(): errors.append(repr(exc))
            try: dest.shutdown(socket.SHUT_WR)
            except OSError: pass
        for args in ((peer, remote, True), (remote, peer, False)):
            thread = threading.Thread(target=forward, args=args, daemon=True); thread.start(); threads.append(thread)
        _, stderr = client.communicate(timeout=45)
        if client.returncode:
            server.terminate(); _, server_error = server.communicate(timeout=5); server = None
            box.terminate(); _, box_error = box.communicate(timeout=5); box = None
            raise RuntimeError(f"client failed: {client.returncode} {stderr!r}, {len(received)} datagrams, server {server_error!r}, box {box_error!r}, relay {errors!r}")
        client = None
        if received != [bytes([i % 256]) * 8192 for i in range(1000)]: raise RuntimeError(f"origin received {len(received)} incorrect or out-of-order packets")
        if errors: raise RuntimeError(f"relay errors: {errors!r}")
        server.terminate(); _, stderr = server.communicate(timeout=5)
        if server.returncode: raise RuntimeError(f"server shutdown: {stderr!r}")
        server = None
        print("UoT inbound real TCP backpressure resumes through sing-box with 1000 ordered 8192-byte round trips")
    finally:
        stop.set()
        for sock in (peer, remote):
            if sock:
                try: sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                sock.close()
        for process in (client, server, box):
            if process and process.poll() is None: process.terminate(); process.communicate(timeout=5)
        for thread in threads: thread.join(timeout=1)
