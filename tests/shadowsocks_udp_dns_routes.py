"""Test domain-selected DNS upstreams through the SS-2022 UDP listener."""
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
mode = sys.argv[2] if len(sys.argv)>2 else "dns-routes"
configured = mode.startswith("config-")
if configured:
    mode = "dns-" + mode.removeprefix("config-")
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")

def exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count-len(data))
        if not part: raise RuntimeError("SOCKS EOF")
        data += part
    return data

with tempfile.TemporaryDirectory(prefix="nexus-dns-routes-") as directory:
    for size in (16, 32):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fallback, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as selected, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            for sock in (fallback, selected, target):
                sock.bind(("127.0.0.1", 0)); sock.settimeout(3)
            errors = []
            def dns_peer(sock, expected):
                try:
                    for _ in range(len(expected)*2):
                        query, peer = sock.recvfrom(512)
                        if not any(query[12:].startswith(name) for name in expected):
                            raise RuntimeError(f"wrong DNS route: {query!r}")
                        kind = int.from_bytes(query[-4:-2], "big")
                        response = bytearray(query); response[2:4] = b"\x81\x80"
                        if kind == 1:
                            response[7] = 1
                            response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                        else:
                            response[9] = 1
                            zone = bytes((0xc0, 13+query[12]))
                            response.extend(zone+b"\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18"+zone+zone+bytes(16)+struct.pack("!I",60))
                        sock.sendto(response, peer)
                except Exception as exc: errors.append(exc)
            def target_peer():
                try:
                    for _ in range(3):
                        data, peer = target.recvfrom(65535); target.sendto(data, peer)
                except Exception as exc: errors.append(exc)
            fallback_names = [b"\x03dns\x04test\x00"] if mode=="dns-chain" else [b"\x01b\x04test\x00"]
            selected_names = [b"\x01a\x04test\x00", b"\x01x\x01a\x04test\x00"]
            if mode in ("dns-chain", "dns-chain-system"): selected_names.append(b"\x01b\x04test\x00")
            threads = [threading.Thread(target=dns_peer, args=(selected, selected_names)), threading.Thread(target=target_peer)]
            if mode!="dns-chain-system": threads.append(threading.Thread(target=dns_peer, args=(fallback, fallback_names)))
            for thread in threads: thread.start()
            env = os.environ.copy(); env["NEXUS_TEST_DNS_PORT"] = str(selected.getsockname()[1])
            if configured:
                with socket.socket() as reserve:
                    reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
                key = pathlib.Path(directory) / "key"
                key.write_text(base64.b64encode(bytes(range(size))).decode() + "\n"); key.chmod(0o600)
                root = ('server "root" type="local";' if mode == "dns-chain-system" else
                        f'server "root" type="udp" host="127.0.0.1" port={fallback.getsockname()[1]};')
                if mode in ("dns-chain", "dns-chain-system"):
                    host = "localhost" if mode == "dns-chain-system" else "dns.test"
                    dns = f'{root} server "leaf" type="udp" host="{host}" port={selected.getsockname()[1]} domain-resolver="root"; final "leaf";'
                else:
                    dns = f'{root} server "leaf" type="udp" host="127.0.0.1" port={selected.getsockname()[1]}; rule domain-suffix="a.test" server="leaf"; final "root";'
                path = pathlib.Path(directory) / "server.kdl"
                path.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ shadowsocks "ss" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }} }}
outbounds {{ direct "direct"; block "reject"; }}
routing {{ final "direct"; }}
dns {{ {dns} }}
''')
                server = subprocess.Popen(["stdbuf", "-oL", fixture, "run", "--config", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, env=env)
            else:
                server = subprocess.Popen([fixture, str(size), str(fallback.getsockname()[1]), mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
            box = None
            try:
                if configured:
                    if not select.select([server.stdout], [], [], 10)[0] or b"listening" not in server.stdout.readline():
                        raise RuntimeError("configured listener failed to start")
                else:
                    port = int(server.stdout.readline())
                with socket.socket() as reserve:
                    reserve.bind(("127.0.0.1", 0)); socks_port = reserve.getsockname()[1]
                config = {"log": {"level": "warn"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
                          "outbounds": [{"type": "shadowsocks", "tag": "edge", "server": "127.0.0.1", "server_port": port,
                          "method": f"2022-blake3-aes-{size*8}-gcm", "password": base64.b64encode(bytes(range(size))).decode()}], "route": {"final": "edge"}}
                path = pathlib.Path(directory) / f"{size}.json"; path.write_text(json.dumps(config))
                subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
                box = subprocess.Popen(["sing-box", "run", "-c", path], stderr=subprocess.PIPE)
                deadline = time.monotonic()+2
                while True:
                    try: client = socket.create_connection(("127.0.0.1", socks_port), timeout=.2); break
                    except OSError:
                        if time.monotonic()>deadline: raise
                        time.sleep(.02)
                with client, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    client.settimeout(2); udp.bind(("127.0.0.1", 0)); udp.settimeout(2)
                    client.sendall(b"\x05\x01\x00")
                    if exact(client, 2) != b"\x05\x00": raise RuntimeError("greeting")
                    client.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01"+struct.pack("!H", udp.getsockname()[1]))
                    if exact(client, 4) != b"\x05\x00\x00\x01": raise RuntimeError("association")
                    relay = exact(client, 6); endpoint = ("127.0.0.1", struct.unpack("!H", relay[4:])[0])
                    for name in (b"a.test", b"x.a.test", b"b.test"):
                        header = b"\x00\x00\x00\x03"+bytes([len(name)])+name+struct.pack("!H", target.getsockname()[1])
                        udp.sendto(header+name, endpoint)
                        try: data, _ = udp.recvfrom(65535)
                        except TimeoutError as exc: raise RuntimeError(f"DNS errors: {errors}, request: {name!r}") from exc
                        if not data.endswith(name): raise RuntimeError(f"unexpected response {data!r}")
                for thread in threads: thread.join(timeout=3)
                if any(t.is_alive() for t in threads) or errors: raise RuntimeError(f"DNS/target failure: {errors}")
                if configured: server.send_signal(signal.SIGTERM)
                if server.wait(timeout=5): raise RuntimeError(f"listener failed: {server.returncode}, {server.stderr.read()}")
            finally:
                if box is not None: box.terminate(); box.communicate(timeout=3)
                if server.poll() is None: server.kill(); server.communicate()
                for thread in threads: thread.join(timeout=4)
print("SS-2022 UDP DNS routes and bootstrap with sing-box passed")
