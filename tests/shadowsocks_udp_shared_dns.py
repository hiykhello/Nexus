"""Two configured SS-2022 UDP groups share DNS without mixing views."""
import base64
import collections
import json
import pathlib
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

nexus = pathlib.Path(sys.argv[1]).resolve()
local = "--local" in sys.argv
if local and "--inside" not in sys.argv:
    subprocess.run(["unshare", "-Urnm", sys.executable, __file__, str(nexus), "--local", "--inside"], check=True)
    sys.exit(0)
if local:
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
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
            raise RuntimeError("SOCKS connection closed")
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


def packet(name, port, payload):
    return b"\x00\x00\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", port) + payload


with tempfile.TemporaryDirectory(prefix="nexus-ss-shared-dns-") as directory:
    root = pathlib.Path(directory)
    if local:
        (root / "resolv.conf").write_text("nameserver 127.0.0.1\noptions timeout:2 attempts:1\n")
        (root / "hosts").write_text("127.0.0.1 localhost\n")
        for name, target_file in (("resolv.conf", "/etc/resolv.conf"), ("hosts", "/etc/hosts")):
            subprocess.run(["mount", "--bind", root / name, target_file], check=True)
    keys = [bytes(range(16)), bytes(range(16, 32))]
    key_files = []
    for index, key in enumerate(keys):
        path = root / f"key-{index}"
        path.write_text(base64.b64encode(key).decode() + "\n")
        path.chmod(0o600)
        key_files.append(path)

    for disabled in (False, True):
        stop = threading.Event()
        errors = []
        queries = [[], []]
        pending = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as root_dns, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as leaf_dns, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target, \
             socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target_tcp:
            root_dns.bind(("127.0.0.1", 0))
            leaf_dns.bind(("127.0.0.1", 53 if local else 0))
            target.bind(("127.0.0.2", 0))
            target_tcp.bind(target.getsockname())
            target_tcp.listen(4)
            target_tcp.settimeout(3)
            for sock in (root_dns, leaf_dns, target):
                sock.settimeout(.2)

            def dns_peer(index, sock):
                try:
                    while not stop.is_set():
                        try:
                            query, peer = sock.recvfrom(512)
                        except TimeoutError:
                            continue
                        name, kind = query[12:-4], int.from_bytes(query[-4:-2], "big")
                        if index == 1 and b"pending-" in name:
                            pending.append(name)
                            continue
                        if name != b"\x06shared\x04test\x00" or kind not in (1, 28):
                            raise RuntimeError(f"unexpected DNS request {index}: {query!r}")
                        queries[index].append(kind)
                        response = bytearray(query)
                        response[2:4] = b"\x81\x80"
                        if kind == 1:
                            response[7] = 1
                            address = b"\x7f\x00\x00\x01" if index == 0 else b"\x7f\x00\x00\x02"
                            response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + address)
                        else:
                            # SOA with minimum TTL 60 makes the AAAA NODATA cacheable.
                            zone = b"\xc0\x13"
                            response[9] = 1
                            response.extend(zone + b"\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18" +
                                            zone + zone + bytes(16) + struct.pack("!I", 60))
                        sock.sendto(response, peer)
                except Exception as exc:
                    errors.append(exc)

            def echo_peer():
                try:
                    while not stop.is_set():
                        try:
                            data, peer = target.recvfrom(65535)
                        except TimeoutError:
                            continue
                        target.sendto(data, peer)
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=dns_peer, args=(0, root_dns)),
                       threading.Thread(target=dns_peer, args=(1, leaf_dns)),
                       threading.Thread(target=echo_peer)]
            for thread in threads:
                thread.start()
            ports = [free_port(), free_port()]
            while ports[0] == ports[1]:
                ports[1] = free_port()
            socks_port = free_port()
            while socks_port in ports:
                socks_port = free_port()
            config = root / "server.kdl"
            cache_option = "disable-cache #true;" if disabled else ""
            dns_config = (f'server "local" type="local"; final "local"; {cache_option}' if local else
                          f'server "root" type="udp" host="127.0.0.1" port={root_dns.getsockname()[1]}; '
                          f'server "leaf" type="udp" host="shared.test" port={leaf_dns.getsockname()[1]} domain-resolver="root"; '
                          f'final "leaf"; {cache_option}')
            upstream_queries = queries[1:] if local else queries
            config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{
 shadowsocks "first" {{ listen host="127.0.0.1" port={ports[0]}; method "2022-blake3-aes-128-gcm"; key-file "{key_files[0]}"; }}
 shadowsocks "second" {{ listen host="127.0.0.1" port={ports[1]}; method "2022-blake3-aes-128-gcm"; key-file "{key_files[1]}"; }}
 socks5 "tcp" {{ listen host="127.0.0.1" port={socks_port}; authentication "none"; }}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
dns {{
 {dns_config}
}}
''')
            server = subprocess.Popen(["stdbuf", "-oL", nexus, "run", "--config", config],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            boxes, clients = [], []
            try:
                for _ in range(len(ports) + 1):
                    if not select.select([server.stdout], [], [], 10)[0] or b"listening" not in server.stdout.readline():
                        raise RuntimeError("configured listener failed to start")
                for index, port in enumerate(ports):
                    client_port = free_port()
                    box_config = {"log": {"level": "warn"},
                                  "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": client_port}],
                                  "outbounds": [{"type": "shadowsocks", "tag": "edge", "server": "127.0.0.1",
                                                 "server_port": port, "method": "2022-blake3-aes-128-gcm",
                                                 "password": base64.b64encode(keys[index]).decode()}],
                                  "route": {"final": "edge"}}
                    path = root / f"client-{index}.json"
                    path.write_text(json.dumps(box_config))
                    subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
                    boxes.append(subprocess.Popen(["sing-box", "run", "-c", path], stderr=subprocess.PIPE))
                    clients.append(associate(client_port))

                # Both views resolve the same name: root must return the leaf
                # server at .1, while leaf must return the target at .2.
                for index, (_, udp, endpoint) in enumerate(clients):
                    payload = f"warm-{index}".encode()
                    udp.sendto(packet(b"shared.test", target.getsockname()[1], payload), endpoint)
                    response, _ = udp.recvfrom(65535)
                    if not response.endswith(payload):
                        raise RuntimeError(f"unexpected UDP response: {response!r}")
                    expected = index + 1 if disabled else 1
                    for upstream in upstream_queries:
                        if collections.Counter(upstream) != {1: expected, 28: expected}:
                            raise RuntimeError(f"unexpected DNS counts, disabled={disabled}: {queries!r}")

                # The two groups may also hit the shared cache concurrently.
                for index, (_, udp, endpoint) in enumerate(clients):
                    udp.sendto(packet(b"shared.test", target.getsockname()[1], f"parallel-{index}".encode()), endpoint)
                for index, (_, udp, _) in enumerate(clients):
                    response, _ = udp.recvfrom(65535)
                    if not response.endswith(f"parallel-{index}".encode()):
                        raise RuntimeError(f"unexpected parallel response: {response!r}")
                expected = 4 if disabled else 1
                for upstream in upstream_queries:
                    if collections.Counter(upstream) != {1: expected, 28: expected}:
                        raise RuntimeError(f"unexpected concurrent DNS counts: {queries!r}")

                # A TCP worker must consume the same cached view as the SS UDP executor.
                with socket.create_connection(("127.0.0.1", socks_port), timeout=3) as tcp:
                    tcp.settimeout(3)
                    tcp.sendall(b"\x05\x01\x00")
                    if exact(tcp, 2) != b"\x05\x00": raise RuntimeError("TCP greeting")
                    name = b"shared.test"
                    tcp.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", target.getsockname()[1]))
                    if exact(tcp, 10)[:3] != b"\x05\x00\x00": raise RuntimeError("TCP connect")
                    with target_tcp.accept()[0] as peer:
                        tcp.sendall(b"tcp-shared")
                        if exact(peer, 10) != b"tcp-shared": raise RuntimeError("TCP upstream payload")
                        peer.sendall(b"ok")
                        if exact(tcp, 2) != b"ok": raise RuntimeError("TCP reply")
                expected = 5 if disabled else 1
                for upstream in upstream_queries:
                    if collections.Counter(upstream) != {1: expected, 28: expected}:
                        raise RuntimeError(f"TCP/UDP shared DNS counts: {queries!r}")

                # Suspend identical requests across TCP and both UDP listeners;
                # cached mode should issue one underlying query, then drain it.
                pending_tcp = socket.create_connection(("127.0.0.1", socks_port), timeout=3)
                pending_tcp.settimeout(3)
                pending_tcp.sendall(b"\x05\x01\x00")
                if exact(pending_tcp, 2) != b"\x05\x00": raise RuntimeError("pending TCP greeting")
                pending_name = b"pending-shared.test"
                pending_tcp.sendall(b"\x05\x01\x00\x03" + bytes([len(pending_name)]) + pending_name + struct.pack("!H", target.getsockname()[1]))
                for _, udp, endpoint in clients:
                    udp.sendto(packet(pending_name, target.getsockname()[1], b"pending-shared"), endpoint)
                expected_pending = 3 if disabled else 1
                deadline = time.monotonic() + 3
                while len(pending) < expected_pending and time.monotonic() < deadline:
                    time.sleep(.01)
                time.sleep(.2)
                if len(pending) != expected_pending or errors:
                    raise RuntimeError(f"TCP/UDP pending queries: {pending!r}, {errors!r}")
                pending.clear()
                pending_tcp.close()

                # Leave one DNS operation on each listener pending at shutdown.
                for index, (_, udp, endpoint) in enumerate(clients):
                    name = f"pending-{index}.test".encode()
                    udp.sendto(packet(name, target.getsockname()[1], b"pending"), endpoint)
                deadline = time.monotonic() + 3
                while len(pending) < 2 and time.monotonic() < deadline:
                    time.sleep(.01)
                if len(pending) != 2 or errors:
                    raise RuntimeError(f"pending DNS requests not observed: {pending!r}, {errors!r}")
                start = time.monotonic()
                server.send_signal(signal.SIGTERM)
                _, stderr = server.communicate(timeout=4)
                if server.returncode or time.monotonic() - start > 2:
                    raise RuntimeError(f"server failed to drain: {server.returncode}, {stderr!r}")
            finally:
                for tcp, udp, _ in clients:
                    tcp.close()
                    udp.close()
                for box in boxes:
                    box.terminate()
                    box.communicate(timeout=3)
                if server.poll() is None:
                    server.kill()
                    server.communicate()
                stop.set()
                for thread in threads:
                    thread.join(timeout=3)
                if errors or any(thread.is_alive() for thread in threads):
                    raise RuntimeError(f"peer failure: {errors!r}")
print(f"TCP/SS UDP {'local' if local else 'explicit'} shared DNS, negative cache, coalescing, disabled cache and pending shutdown passed")
