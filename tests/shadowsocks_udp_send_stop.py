"""Exercise a bounded SS UDP send queue with delayed sends and failures."""
import base64
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
backend = sys.argv[2]
mode = sys.argv[3] if len(sys.argv) > 3 else "stop"
if mode not in ("stop", "fault", "task-fault", "full"):
    raise ValueError("expected stop, fault, task-fault, or full")
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")


def exact(sock, count):
    result = b""
    while len(result) < count:
        data = sock.recv(count - len(result))
        if not data:
            raise RuntimeError("SOCKS EOF")
        result += data
    return result


with tempfile.TemporaryDirectory(prefix="nexus-udp-send-stop-") as directory, \
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target, socket.socket() as reserve:
    target.bind(("127.0.0.1", 0))
    target.settimeout(.1)
    reserve.bind(("127.0.0.1", 0))
    socks_port = reserve.getsockname()[1]
    reserve.close()
    received, errors = [], []
    stop = threading.Event()

    def echo():
        try:
            while not stop.is_set():
                try:
                    payload, peer = target.recvfrom(65535)
                except TimeoutError:
                    continue
                received.append(payload)
                target.sendto(payload, peer)
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=echo)
    worker.start()
    env = dict(os.environ, NEXUS_TEST_UDP_BACKEND=backend)
    listener = subprocess.Popen([fixture, "16", "53", "send-" + mode], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env)
    box, tcp, udp = None, None, None
    try:
        port = int(listener.stdout.readline())
        config = {"log": {"level": "warn"},
                  "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
                  "outbounds": [{"type": "shadowsocks", "tag": "edge", "server": "127.0.0.1",
                                 "server_port": port, "method": "2022-blake3-aes-128-gcm",
                                 "password": base64.b64encode(bytes(range(16))).decode()}],
                  "route": {"final": "edge"}}
        path = pathlib.Path(directory) / "client.json"
        path.write_text(json.dumps(config))
        box = subprocess.Popen(["sing-box", "run", "-c", path], stderr=subprocess.PIPE)
        deadline = time.monotonic() + 3
        while True:
            try:
                tcp = socket.create_connection(("127.0.0.1", socks_port), timeout=.2)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.02)
        tcp.settimeout(3)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        tcp.sendall(b"\x05\x01\x00")
        if exact(tcp, 2) != b"\x05\x00":
            raise RuntimeError("greeting failed")
        tcp.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.getsockname()[1]))
        if exact(tcp, 4) != b"\x05\x00\x00\x01":
            raise RuntimeError("association failed")
        endpoint = ("127.0.0.1", struct.unpack("!H", exact(tcp, 6)[4:])[0])
        header = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target.getsockname()[1])
        count = 40 if mode == "full" else 12
        for index in range(count):
            udp.sendto(header + struct.pack("!I", index), endpoint)
        if mode == "full":
            udp.settimeout(5)
            for index in range(count):
                data, _ = udp.recvfrom(65535)
                expected = header + struct.pack("!I", index)
                if data != expected:
                    raise RuntimeError(f"wrong reply at {index}: {data!r}")
        if listener.wait(timeout=5) != (4 if mode in ("fault", "task-fault") else 0):
            raise RuntimeError(f"listener exit {listener.returncode}: {listener.stderr.read()}")
        minimum = 1 if mode == "fault" else 40 if mode == "full" else 3
        if len(received) < minimum:
            raise RuntimeError(f"too few packets reached target: {len(received)}")
    finally:
        if tcp:
            tcp.close()
        if udp:
            udp.close()
        if box:
            box.terminate()
            box.communicate(timeout=3)
        if listener.poll() is None:
            listener.kill()
            listener.communicate(timeout=3)
        stop.set()
        worker.join(timeout=3)
        if worker.is_alive() or errors:
            raise RuntimeError(f"target failure: {errors}")
print(f"SS UDP queued-send {mode} and drain passed ({backend})")
