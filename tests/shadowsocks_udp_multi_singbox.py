"""Exercise two address-family listeners concurrently with sing-box clients."""
import base64
import json
import os
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

fixture = pathlib.Path(sys.argv[1]).resolve()
configured = len(sys.argv) > 2 and sys.argv[2] == "config"
observer = pathlib.Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else None
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")

def exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise RuntimeError("SOCKS EOF")
        data += part
    return data

with tempfile.TemporaryDirectory(prefix="nexus-udp-multi-") as directory:
    for size in (16, 32):
        read_fd, write_fd = os.pipe() if observer else (-1, -1)
        env = os.environ.copy()
        if observer:
            env.update(LD_PRELOAD=str(observer), NEXUS_TEST_UDP_OBSERVE_FD=str(write_fd))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            target.bind(("127.0.0.1", 0))
            target.settimeout(3)
            errors, sources = [], set()
            def echo():
                try:
                    for i in range(8):
                        data, source = target.recvfrom(65535)
                        sources.add(source)
                        # This upstream reply cannot fit after SS-2022 framing.
                        if i == 0:
                            target.sendto(b"x" * 65500, source)
                            if observer and (not select.select([read_fd], [], [], 2)[0] or os.read(read_fd, 1) != b"1"):
                                raise RuntimeError("relay did not receive the large datagram")
                        target.sendto(data, source)
                except Exception as exc:
                    errors.append(exc)
            thread = threading.Thread(target=echo)
            thread.start()
            if configured:
                ports = []
                for _ in range(2):
                    with socket.socket() as reserve:
                        reserve.bind(("127.0.0.1", 0))
                        ports.append(reserve.getsockname()[1])
                if ports[0] == ports[1]: raise RuntimeError("port collision")
                key = pathlib.Path(directory) / "key"
                key.write_text(base64.b64encode(bytes(range(size))).decode() + "\n")
                key.chmod(0o600)
                path = pathlib.Path(directory) / "server.kdl"
                path.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{
 shadowsocks "a" {{ listen host="127.0.0.1" port={ports[0]}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }}
 shadowsocks "b" {{ listen host="127.0.0.1" port={ports[1]}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }}
}}
outbounds {{ direct "direct"; block "reject"; }}
routing {{ final "direct"; }}
''')
                server = subprocess.Popen(["stdbuf", "-oL", fixture, "run", "--config", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                                          env=env, pass_fds=(write_fd,) if observer else ())
            else:
                server = subprocess.Popen([fixture, str(size), "53", "multi6"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                          env=env, pass_fds=(write_fd,) if observer else ())
            boxes, clients = [], []
            try:
                if configured:
                    for _ in ports:
                        if not select.select([server.stdout], [], [], 10)[0] or b"listening" not in server.stdout.readline():
                            raise RuntimeError("configured listener failed to start")
                else:
                    ports = [int(server.stdout.readline()), int(server.stdout.readline())]
                socks_ports = []
                for index, host in enumerate(("127.0.0.1", "127.0.0.1") if configured else ("127.0.0.1", "::1")):
                    with socket.socket() as reserve:
                        reserve.bind(("127.0.0.1", 0))
                        socks_port = reserve.getsockname()[1]
                    config = {"log": {"level": "warn"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
                              "outbounds": [{"type": "shadowsocks", "tag": "edge", "server": host, "server_port": ports[index],
                              "method": f"2022-blake3-aes-{size*8}-gcm", "password": base64.b64encode(bytes(range(size))).decode()}],
                              "route": {"final": "edge"}}
                    path = pathlib.Path(directory) / f"{size}-{index}.json"
                    path.write_text(json.dumps(config))
                    subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
                    boxes.append(subprocess.Popen(["sing-box", "run", "-c", path], stderr=subprocess.PIPE))
                    deadline = time.monotonic() + 2
                    while True:
                        try:
                            probe = socket.create_connection(("127.0.0.1", socks_port), timeout=.2)
                            probe.close()
                            break
                        except OSError:
                            if time.monotonic() > deadline:
                                raise
                            time.sleep(.02)
                    socks_ports.append(socks_port)
                header = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target.getsockname()[1])
                for i in range(8):
                    tcp = socket.create_connection(("127.0.0.1", socks_ports[i % 2]), timeout=2)
                    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp.bind(("127.0.0.1", 0))
                    udp.settimeout(2)
                    clients.append((tcp, udp))
                    tcp.sendall(b"\x05\x01\x00")
                    if exact(tcp, 2) != b"\x05\x00": raise RuntimeError("greeting")
                    tcp.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.getsockname()[1]))
                    if exact(tcp, 4) != b"\x05\x00\x00\x01": raise RuntimeError("association")
                    relay = exact(tcp, 6)
                    udp.sendto(header + f"client-{i}".encode(), ("127.0.0.1", struct.unpack("!H", relay[4:])[0]))
                for i, (_, udp) in enumerate(clients):
                    data, _ = udp.recvfrom(65535)
                    if data != header + f"client-{i}".encode(): raise RuntimeError(f"wrong reply {i}: {data!r}")
                thread.join(timeout=2)
                if thread.is_alive() or errors or len(sources) != 8: raise RuntimeError(f"target errors: {errors}, sources: {sources}")
                if configured: server.send_signal(signal.SIGTERM)
                if server.wait(timeout=5): raise RuntimeError(f"listener failed: {server.returncode}, {server.stderr.read()}")
            finally:
                for tcp, udp in clients:
                    tcp.close()
                    udp.close()
                for box in boxes:
                    box.terminate()
                    box.communicate(timeout=3)
                if server.poll() is None:
                    server.kill()
                    server.communicate()
            thread.join(timeout=4)
        if observer:
            os.close(read_fd)
            os.close(write_fd)
print("SS-2022 UDP concurrent " + ("configured" if configured else "mixed-family") + " listeners with sing-box passed")
