#!/usr/bin/env python3
"""Exercise Shadowsocks 2022 TCP EIH and ChaCha20 with independent sing-box peers."""

import base64
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

from detour_network import running, socks
from dns_rule_support import Echo, datagram_request, exact, free_port, nexus_process, udp_client
from proxy_listener_reload_network import reload


def material(root, name, fill, size):
    path = root / name
    encoded = base64.b64encode(bytes([fill]) * size).decode()
    path.write_text(encoded + "\n")
    path.chmod(0o600)
    return path, encoded


def transfer(front, target):
    payload = b"Shadowsocks TCP EIH"
    client, _ = socks(front, 1, ("127.0.0.1", target))
    with client:
        client.sendall(payload)
        assert exact(client, len(payload)) == payload
        client.shutdown(socket.SHUT_WR)
        assert client.recv(1) == b""


def reject(front, origin):
    before = len(origin.accepted)
    try:
        client, _ = socks(front, 1, ("127.0.0.1", origin.port))
        with client:
            client.sendall(b"unauthorized")
            assert client.recv(1) == b""
    except (BrokenPipeError, ConnectionResetError):
        pass
    assert len(origin.accepted) == before


class DatagramTap:
    def __init__(self, port):
        self.upstream = ("127.0.0.1", port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.first = None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.relay)

    def relay(self):
        client = None
        while not self.stop.is_set():
            try:
                data, source = self.socket.recvfrom(65535)
            except TimeoutError:
                continue
            if source == self.upstream:
                if client:
                    self.socket.sendto(data, client)
            else:
                client = source
                if self.first is None:
                    self.first = data
                self.socket.sendto(data, self.upstream)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(2)
        self.socket.close()

    def replay(self):
        assert self.first is not None
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as different_peer:
            different_peer.sendto(self.first, self.upstream)


def scenario(binary, root, size, native=False):
    method = f"2022-blake3-aes-{size*8}-gcm"
    identity, i_key = material(root, "identity", 1, size)
    alice, a_key = material(root, "alice", 2, size)
    bob, b_key = material(root, "bob", 3, size)
    _, wrong_key = material(root, "wrong", 4, size)
    box_front, nexus_edge, nexus_front, box_edge = (free_port() for _ in range(4))
    box_server = root / "box-server.json"
    box_server.write_text(json.dumps({
        "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": box_edge,
                       "method": method, "password": i_key,
                       "users": [{"name": "alice", "password": a_key}, {"name": "bob", "password": b_key}]}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }))
    nexus_client = root / "nexus-client.kdl"
    nexus_client.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={nexus_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{
 server host="127.0.0.1" port={box_edge}; method "{method}";
 identity-key-file "{identity}"; key-file "{alice}"; udp-over-tcp "v2";
}}
routing {{ default-outbound "edge"; }}
''')

    nexus_server = root / "nexus-server.kdl"
    nexus_server.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{
 shadowsocks "edge" {{
   listen host="127.0.0.1" port={nexus_edge}; method "{method}"; key-file "{identity}";
   authentication {{ user "alice" key-file="{alice}"; user "bob" key-file="{bob}"; }}
 }}
}}
outbounds {{ direct "direct"; block "blocked"; }}
routing {{
  rule-set "blocked" format="kdl" path="blocked.kdl";
  rule kind="rule-set" value="blocked" outbound="blocked"; default-outbound "direct";
}}
''')
    box_client = root / "box-client.json"

    def peer_client(key, *, udp_over_tcp=True, edge=nexus_edge, front=box_front):
        config = box_client.with_name(f"box-client-{front}.json")
        config.write_text(json.dumps({
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": front}],
            "outbounds": [{"type": "shadowsocks", "tag": "edge", "server": "127.0.0.1", "server_port": edge,
                           "method": method, "password": f"{i_key}:{key}",
                           "udp_over_tcp": {"enabled": udp_over_tcp, "version": 2}}],
        }))
        return running(["sing-box", "run", "-c", config], front, root / f"box-client-{front}.log")

    with Echo() as origin, Echo() as guarded:
        (root / "blocked.kdl").write_text(f'''schema-version 2
kind "predicate"
rule type="and" {{ rule type="auth-user" value="bob"; rule type="port" value="{guarded.port}"; }}
''')
        with running(["sing-box", "run", "-c", box_server], box_edge, root / "box-server.log"):
            with nexus_process(binary, nexus_client), udp_client(nexus_front) as (client, relay):
                transfer(nexus_front, origin.port)
                datagram_request(client, relay, origin.port, "127.0.0.1")

        with nexus_process(binary, nexus_server) as server:
            with peer_client(a_key), udp_client(box_front) as (client, relay):
                transfer(box_front, guarded.port)
                datagram_request(client, relay, origin.port, "127.0.0.1")
            with peer_client(b_key):
                transfer(box_front, origin.port)
                reject(box_front, guarded)
            with peer_client(wrong_key):
                reject(box_front, origin)
            if native:
                with DatagramTap(nexus_edge) as tap, peer_client(a_key, udp_over_tcp=False, edge=tap.port):
                    with udp_client(box_front) as (client, relay):
                        datagram_request(client, relay, guarded.port, "127.0.0.1")
                        seen = len(guarded.received)
                        tap.replay()
                        time.sleep(.12)
                        assert len(guarded.received) == seen
                        datagram_request(client, relay, guarded.port, "127.0.0.1")
                with peer_client(b_key, udp_over_tcp=False), udp_client(box_front) as (client, relay):
                    datagram_request(client, relay, origin.port, "127.0.0.1")
                    datagram_request(client, relay, guarded.port, "127.0.0.1", success=False)
                with peer_client(wrong_key, udp_over_tcp=False), udp_client(box_front) as (client, relay):
                    before = len(origin.received)
                    datagram_request(client, relay, origin.port, "127.0.0.1", success=False)
                    assert len(origin.received) == before
                carol, c_key = material(root, "carol", 5, size)
                authenticated = nexus_server.read_text()
                next_front = free_port()
                with peer_client(a_key, udp_over_tcp=False), udp_client(box_front) as (client, relay):
                    datagram_request(client, relay, guarded.port, "127.0.0.1")
                    candidate = nexus_server.with_suffix(".candidate")
                    candidate.write_text(authenticated.replace(
                        f'user "alice" key-file="{alice}";', f'user "carol" key-file="{carol}";'))
                    candidate.replace(nexus_server)
                    assert reload(server) == 2
                    datagram_request(client, relay, guarded.port, "127.0.0.1")
                    with peer_client(c_key, udp_over_tcp=False, front=next_front), udp_client(next_front) as (new, route):
                        datagram_request(new, route, guarded.port, "127.0.0.1")
                    with peer_client(a_key, udp_over_tcp=False, front=next_front), udp_client(next_front) as (new, route):
                        datagram_request(new, route, guarded.port, "127.0.0.1", success=False)


def chacha20(binary, root):
    method = "2022-blake3-chacha20-poly1305"
    key_file, key = material(root, "chacha", 5, 32)
    _, wrong = material(root, "wrong", 6, 32)
    box_front, nexus_edge, nexus_front, box_edge = (free_port() for _ in range(4))
    box_server = root / "box-server.json"
    box_server.write_text(json.dumps({
        "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": box_edge,
                       "method": method, "password": key}],
        "outbounds": [{"type": "direct"}],
    }))
    nexus_client = root / "nexus-client.kdl"
    nexus_client.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={nexus_front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="shadowsocks" {{
 server host="127.0.0.1" port={box_edge}; method "{method}"; key-file "{key_file}"; udp-over-tcp "v2";
}}
routing {{ default-outbound "edge"; }}
''')
    nexus_server = root / "nexus-server.kdl"
    nexus_server.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ shadowsocks "edge" {{ listen host="127.0.0.1" port={nexus_edge}; method "{method}"; key-file "{key_file}"; }} }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    box_client = root / "box-client.json"

    def peer_client(secret):
        box_client.write_text(json.dumps({
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": box_front}],
            "outbounds": [{"type": "shadowsocks", "server": "127.0.0.1", "server_port": nexus_edge,
                           "method": method, "password": secret}],
        }))
        return running(["sing-box", "run", "-c", box_client], box_front, root / "chacha-client.log")

    with Echo() as origin:
        with running(["sing-box", "run", "-c", box_server], box_edge, root / "chacha-server.log"):
            with nexus_process(binary, nexus_client), udp_client(nexus_front) as (client, relay):
                transfer(nexus_front, origin.port)
                datagram_request(client, relay, origin.port, "127.0.0.1")
        with nexus_process(binary, nexus_server):
            with peer_client(key), udp_client(box_front) as (client, relay):
                transfer(box_front, origin.port)
                for _ in range(3):
                    datagram_request(client, relay, origin.port, "127.0.0.1")
            with peer_client(wrong), udp_client(box_front) as (client, relay):
                reject(box_front, origin)
                before = len(origin.received)
                datagram_request(client, relay, origin.port, "127.0.0.1", success=False)
                assert len(origin.received) == before
    print("SS-2022 ChaCha20 TCP in both directions, UoT, native XChaCha20 UDP ingress and wrong key rejection passed")


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    assert f"Revision: {revision}" in subprocess.run(
        ["sing-box", "version"], check=True, capture_output=True, text=True).stdout
    with tempfile.TemporaryDirectory(prefix="nexus-ss-eih-") as directory:
        root = Path(directory)
        if "--chacha" in sys.argv[2:]:
            chacha20(binary, root)
        else:
            for size in (16, 32):
                native = "--native" in sys.argv[2:]
                scenario(binary, root, size, native)
                coverage = "TCP/UoT and native UDP EIH with replay rejection and same-bind reload" if native else "TCP EIH and UoT"
                print(f"SS-2022 AES-{size * 8} {coverage}, authenticated routing and rejection passed", flush=True)
