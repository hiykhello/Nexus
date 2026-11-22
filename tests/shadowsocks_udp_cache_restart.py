"""Restart the same SS UDP owner with a changed DNS view and live clients."""
import base64
import json
import pathlib
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
options = set(sys.argv[2:])
if options - {"--stale", "--pending", "--coordinated"}:
    raise ValueError("unknown cache restart test option")
stale = "--stale" in options
pending_test = "--pending" in options
coordinated = "--coordinated" in options
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exact(sock, count):
    result = b""
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise RuntimeError("SOCKS EOF")
        result += chunk
    return result


def associate(port):
    deadline = time.monotonic() + 3
    while True:
        try:
            tcp = socket.create_connection(("127.0.0.1", port), timeout=.2)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.02)
    tcp.settimeout(3)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(3)
    tcp.sendall(b"\x05\x01\x00")
    if exact(tcp, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting")
    tcp.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.getsockname()[1]))
    if exact(tcp, 4) != b"\x05\x00\x00\x01":
        raise RuntimeError("SOCKS UDP association")
    endpoint = ("127.0.0.1", struct.unpack("!H", exact(tcp, 6)[4:])[0])
    return tcp, udp, endpoint


def ready(process):
    if not select.select([process.stdout], [], [], 5)[0] or process.stdout.readline() != b"ready\n":
        raise RuntimeError("UDP owner failed to start or restart")


with tempfile.TemporaryDirectory(prefix="nexus-ss-cache-restart-") as directory, \
     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns0, \
     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns1, \
     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target0, \
     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target1:
    root = pathlib.Path(directory)
    for sock in (dns0, dns1):
        sock.bind(("127.0.0.1", 0))
    target0.bind(("127.0.0.1", 0))
    target1.bind(("127.0.0.2", target0.getsockname()[1]))
    sockets = (dns0, dns1, target0, target1)
    stop, errors = threading.Event(), []
    queries, delivered = [0, 0], [[], []]
    held, held_lock = [], threading.Lock()
    refresh_seen, pending_seen = threading.Event(), threading.Event()
    hold_refresh = threading.Event()

    def peers():
        try:
            while not stop.is_set():
                readable, _, _ = select.select(sockets, [], [], .1)
                for sock in readable:
                    data, peer = sock.recvfrom(65535)
                    index = sockets.index(sock)
                    if index < 2:
                        question = data[12:]
                        if pending_test and question == b"\x07pending\x04test\x00\x00\x01\x00\x01":
                            with held_lock:
                                held.append((sock, data, peer))
                                if sum(item[1][12:] == question for item in held) >= (1 if coordinated else 2):
                                    pending_seen.set()
                            continue
                        if question != b"\x05cache\x04test\x00\x00\x01\x00\x01":
                            raise RuntimeError(f"unexpected DNS question: {data!r}")
                        queries[index] += 1
                        if index == 0 and hold_refresh.is_set():
                            with held_lock:
                                held.append((sock, data, peer))
                            refresh_seen.set()
                            continue
                        reply = bytearray(data)
                        reply[2:4] = b"\x81\x80"
                        reply[7] = 1
                        reply.extend(b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!IH", 3 if stale else 60, 4) +
                                     b"\x7f\x00\x00" + bytes([index + 1]))
                        sock.sendto(reply, peer)
                    else:
                        delivered[index - 2].append(data)
                        sock.sendto(data, peer)
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=peers)
    thread.start()
    ports = [free_port(), free_port()]
    while ports[0] == ports[1]:
        ports[1] = free_port()
    owner = subprocess.Popen([fixture, *map(str, ports), str(dns0.getsockname()[1]), str(dns1.getsockname()[1])],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    boxes, clients = [], []
    try:
        ready(owner)
        for index, port in enumerate(ports):
            key = bytes(range(index * 16, (index + 1) * 16))
            socks_port = free_port()
            config = {"log": {"level": "warn"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
                      "outbounds": [{"type": "shadowsocks", "tag": "edge", "server": "127.0.0.1", "server_port": port,
                                     "method": "2022-blake3-aes-128-gcm", "password": base64.b64encode(key).decode()}],
                      "route": {"final": "edge"}}
            path = root / f"client-{index}.json"
            path.write_text(json.dumps(config))
            subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
            boxes.append(subprocess.Popen(["sing-box", "run", "-c", path], stderr=subprocess.PIPE))
            clients.append(associate(socks_port))

        def send(index, payload):
            _, udp, endpoint = clients[index]
            name = b"cache.test"
            udp.sendto(b"\x00\x00\x00\x03" + bytes([len(name)]) + name +
                       struct.pack("!H", target0.getsockname()[1]) + payload, endpoint)
            reply, _ = udp.recvfrom(65535)
            if not reply.endswith(payload):
                raise RuntimeError(f"wrong UDP response: {reply!r}")

        send(0, b"before-0")
        send(1, b"before-1")
        if queries != [1, 0] or delivered != [[b"before-0", b"before-1"], []]:
            raise RuntimeError(f"first cache/view mismatch: {queries!r}, {delivered!r}")
        expected_before = [b"before-0", b"before-1"]
        if stale:
            time.sleep(2.2)
            hold_refresh.set()
            send(0, b"stale-0")
            send(1, b"stale-1")
            expected_before.extend((b"stale-0", b"stale-1"))
            if not refresh_seen.wait(3):
                raise RuntimeError("stale answer did not start a refresh")
            time.sleep(.1)
            if queries != [2, 0] or delivered != [expected_before, []]:
                raise RuntimeError(f"stale refresh was not shared: {queries!r}, {delivered!r}")
        if pending_test:
            for _, udp, endpoint in clients:
                name = b"pending.test"
                udp.sendto(b"\x00\x00\x00\x03" + bytes([len(name)]) + name +
                           struct.pack("!H", target0.getsockname()[1]) + b"pending", endpoint)
            if not pending_seen.wait(3):
                raise RuntimeError("pending queries did not reach DNS")
            if coordinated:
                time.sleep(.1)
                with held_lock:
                    count = sum(item[1][12:] == b"\x07pending\x04test\x00\x00\x01\x00\x01" for item in held)
                if count != 1:
                    raise RuntimeError(f"pending queries were not coordinated: {count}")
        owner.stdin.write(b"restart\n")
        owner.stdin.flush()
        ready(owner)
        with held_lock:
            abandoned = list(held)
        for sock, query, peer in abandoned:
            reply = bytearray(query)
            reply[2:4] = b"\x81\x80"
            reply[7] = 1
            reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
            sock.sendto(reply, peer)
        if abandoned and select.select([entry[1] for entry in clients], [], [], .2)[0]:
            raise RuntimeError("canceled query delivered a late reply")
        send(0, b"after-0")
        send(1, b"after-1")
        if queries != [2 if stale else 1, 1] or delivered != [expected_before, [b"after-0", b"after-1"]]:
            raise RuntimeError(f"restarted cache/view mismatch: {queries!r}, {delivered!r}")
        owner.stdin.write(b"stop\n")
        owner.stdin.flush()
        _, stderr = owner.communicate(timeout=5)
        if owner.returncode or errors:
            raise RuntimeError(f"owner or peer failed: {owner.returncode}, {stderr!r}, {errors!r}")
        print(stderr.decode().strip())
    finally:
        for tcp, udp, _ in clients:
            tcp.close()
            udp.close()
        for box in boxes:
            box.terminate()
            box.communicate(timeout=3)
        if owner.poll() is None:
            owner.kill()
            owner.communicate()
        stop.set()
        thread.join(timeout=3)
        if errors or thread.is_alive():
            raise RuntimeError(f"peer failure: {errors!r}")
print("SS UDP owner restart isolates DNS views and shares the new cache")
