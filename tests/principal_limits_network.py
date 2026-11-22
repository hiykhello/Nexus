#!/usr/bin/env python3
"""Check authenticated connection and stream admission in the production CLI."""

import base64
import contextlib
import json
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import time

from anytls_network import Origin
from anytls_test_peer import Peer, address, datagram
from detour_network import running, socks
from dns_rule_support import Echo, connect, datagram_request, exact, free_port, nexus_process, udp_client
from hy2_outbound_singbox import REVISION
from shadowsocks_identity_network import reject
from proxy_listener_reload_network import reload
from udp_bind_port_network import certificate


def usage(binary, control, index, user, **expected):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        result = subprocess.check_output([binary, "control", control, "user-usage", str(index)], text=True)
        rows = [dict(field.split("=", 1) for field in shlex.split(line)) for line in result.splitlines()]
        row = next(entry for entry in rows if entry["user"] == user)
        if all(int(row[name.replace("_", "-")]) == value for name, value in expected.items()):
            return
        time.sleep(.02)
    raise AssertionError((user, expected, row))


@contextlib.contextmanager
def socks_auth(front, expected):
    with connect(front) as client:
        client.sendall(b"\x05\x01\x02")
        assert exact(client, 2) == b"\x05\x02"
        client.sendall(b"\x01\x05alice\x05alice")
        assert exact(client, 2) == bytes((1, expected))
        yield client


def mixed(binary, root):
    front = free_port()
    control = root / "control"
    config = root / "mixed.kdl"
    config.write_text(f'''schema-version 1
role "client"
workers 2
control socket="{control}"
inbound "local" type="mixed" {{
 listen host="127.0.0.1" port={front}
 authentication "password" username="alice" password-file="{root / 'alice'}"
 user-limits {{ user "alice" connections=1; }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    with nexus_process(binary, config), Echo() as origin:
        with socks_auth(front, 0) as client, socket.socket(type=socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", 0))
            client.sendall(b"\x05\x03\x00" + address("127.0.0.1", udp.getsockname()[1]))
            reply = exact(client, 10)
            assert reply[:4] == b"\x05\x00\x00\x01"
            relay = socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:], "big")
            datagram_request(udp, relay, origin.port, "127.0.0.1")
            with socks_auth(front, 1):
                pass
            with connect(front) as http:
                target = f"127.0.0.1:{origin.port}"
                auth = base64.b64encode(b"alice:alice").decode()
                http.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
                assert exact(http, 12) == b"HTTP/1.1 429"
            datagram_request(udp, relay, origin.port, "127.0.0.1")
            usage(binary, control, 0, "alice", connections=1, rejected_connections=2)
        usage(binary, control, 0, "alice", connections=0)
        with socks_auth(front, 0) as client:
            client.sendall(b"\x05\x01\x00" + address("127.0.0.1", origin.port))
            assert exact(client, 10)[:2] == b"\x05\x00"
            client.sendall(b"recovered")
            assert exact(client, 9) == b"recovered"


def anytls(binary, root):
    front = free_port()
    control = root / "control"
    config = root / "anytls.kdl"

    def publish(streams):
        candidate = config.with_suffix(".candidate")
        candidate.write_text(f'''schema-version 1
role "server"
workers 2
shutdown-grace-ms 10000
control socket="{control}"
inbound "edge" type="anytls" {{
 listen host="127.0.0.1" port={front}
 authentication {{ user "alice" password-file="{root / 'alice'}"; user "bob" password-file="{root / 'bob'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
 user-limits {{ user "alice" connections=2 streams={streams}; user "bob" connections=1 streams=1; }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        candidate.replace(config)

    publish(2)
    with nexus_process(binary, config) as server, Origin(idle_timeout=6) as origin, Echo() as udp:
        with Peer(root, front, "alice") as alice, Peer(root, front, "bob") as bob:
            first = alice.open("127.0.0.1", origin.port, b"alice")
            alice.ack(first)
            assert alice.read(first, 5) == b"alice"
            second = alice.open("sp.v2.udp-over-tcp.arpa", 0, b"\x00" + address("0.0.0.0", 0))
            alice.ack(second)
            alice.send(second, datagram("127.0.0.1", udp.port, b"before"))
            assert alice.read_datagram(second)[3] == b"before"
            blocked = alice.open("127.0.0.1", origin.port)
            alice.ack(blocked, accepted=False)
            other = bob.open("127.0.0.1", origin.port, b"bob")
            bob.ack(other)
            assert bob.read(other, 3) == b"bob"
            usage(binary, control, 0, "alice", connections=1, streams=2, rejected_streams=1)
            usage(binary, control, 0, "bob", connections=1, streams=1, rejected_streams=0)
            publish(1)
            assert reload(server) == 2
            with Peer(root, front, "alice") as next_alice:
                denied = next_alice.open("127.0.0.1", origin.port)
                next_alice.ack(denied, accepted=False)
                alice.send(second, datagram("127.0.0.1", udp.port, b"after"))
                assert alice.read_datagram(second)[3] == b"after"
                alice.finish(second)
                alice.finish(first)
                usage(binary, control, 0, "alice", connections=2, streams=0, rejected_streams=2)
                allowed = next_alice.open("127.0.0.1", origin.port, b"after")
                next_alice.ack(allowed)
                assert next_alice.read(allowed, 5) == b"after"
                next_alice.finish(allowed)
            bob.finish(other)
        usage(binary, control, 0, "alice", connections=0, streams=0, rejected_streams=2)


def shadowsocks(binary, root, byte_limits=False, ordered=False):
    control = root / "control"
    config = root / "ss.kdl"
    front, peer = free_port(), free_port()
    keys = {}
    for user, number in (("identity", 41), ("alice", 42), ("bob", 43)):
        keys[user] = base64.b64encode(bytes([number]) * 16).decode()
        key = root / f"{user}.key"
        key.write_text(keys[user] + "\n")
        key.chmod(0o600)
    alice_connections = 2 if byte_limits else 1
    alice_limit = " byte-quota=45" if byte_limits else ""
    tcp_program = '''tcp-program unknown="skip" sniff-timeout-ms=1000 udp=#true {
  rule action="route" outbound="direct"
 }''' if ordered else ""
    config.write_text(f'''schema-version 1
role "server"
workers 2
control socket="{control}"
inbounds {{ shadowsocks "ss" {{
 listen host="127.0.0.1" port={front}
 method "2022-blake3-aes-128-gcm"
 key-file "{root / 'identity.key'}"
 authentication {{ user "alice" key-file="{root / 'alice.key'}"; user "bob" key-file="{root / 'bob.key'}"; }}
 user-limits {{ user "alice" connections={alice_connections}{alice_limit}; user "bob" connections=1; }}
}} }}
outbound "direct" type="direct"
routing {{
 {tcp_program}
 default-outbound "direct"
}}
''')

    @contextlib.contextmanager
    def client(user):
        path = root / f"peer-{user}.json"
        port = peer if user == "alice" else free_port()
        path.write_text(json.dumps({
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [{"type": "shadowsocks", "server": "127.0.0.1", "server_port": front,
                           "method": "2022-blake3-aes-128-gcm", "password": f"{keys['identity']}:{keys[user]}"}],
        }))
        with running(["sing-box", "run", "-c", path], port, root / f"peer-{user}.log"):
            yield port

    with nexus_process(binary, config), Origin(idle_timeout=6) as origin, Echo() as datagrams:
        with client("alice") as port, udp_client(port) as (udp, relay):
            if byte_limits:
                with socks(port, 1, ("127.0.0.1", origin.port))[0] as tcp:
                    tcp.sendall(b"alice")
                    assert exact(tcp, 5) == b"alice"
                    datagram_request(udp, relay, datagrams.port, "127.0.0.1")
                    usage(binary, control, 0, "alice", upload=22, download=22, unconfirmed=0)
                    arrived = len(datagrams.received)
                    datagram_request(udp, relay, datagrams.port, "127.0.0.1", success=False)
                    assert len(datagrams.received) == arrived
                    usage(binary, control, 0, "alice", upload=22, download=22, byte_limit_denials=1)
                return
            with socks(port, 1, ("127.0.0.1", origin.port))[0] as tcp:
                tcp.sendall(b"alice")
                assert exact(tcp, 5) == b"alice"
                usage(binary, control, 0, "alice", connections=1)
                datagram_request(udp, relay, datagrams.port, "127.0.0.1", success=False)
                with client("bob") as other, udp_client(other) as (bob, bob_relay):
                    datagram_request(bob, bob_relay, datagrams.port, "127.0.0.1")
                    usage(binary, control, 0, "bob", connections=1, rejected_connections=0)
            usage(binary, control, 0, "alice", connections=0)
            datagram_request(udp, relay, datagrams.port, "127.0.0.1")
            usage(binary, control, 0, "alice", connections=1)
            reject(port, datagrams)
            datagram_request(udp, relay, datagrams.port, "127.0.0.1")


def tls_peer(binary, root, protocol, byte_limits=False, udp_over_stream=False):
    control = root / "control"
    config = root / f"{protocol}.kdl"
    is_quic = protocol in ("hysteria2", "tuic")
    grpc = protocol == "vless-grpc"
    wire_protocol = "vless" if grpc else protocol
    needs_uuid = wire_protocol in ("vless", "tuic")
    with socket.socket(type=socket.SOCK_DGRAM if is_quic else socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        front = reservation.getsockname()[1]
    uuid_files = {}
    for number, user in enumerate(("alice", "bob"), 1):
        uuid = f"00000000-0000-4000-8000-{number:012}"
        path = root / f"{user}.uuid"
        path.write_text(uuid)
        path.chmod(0o600)
        uuid_files[user] = uuid
    def user_config(name):
        fields = {}
        if wire_protocol != "vless":
            fields["password-file"] = root / name
        if needs_uuid:
            fields["uuid-file"] = root / (name + ".uuid")
        return f'user "{name}" ' + " ".join(f'{key}="{value}"' for key, value in fields.items()) + ";"

    users = " ".join(map(user_config, uuid_files))
    transport = f'transport "grpc" {{ service-name "nexus.Service"; authority "localhost:{front}"; }}' if grpc else ""
    alice_streams = " streams=1" if is_quic else " streams=0" if protocol == "vless" else ""
    bob_streams = " streams=1" if is_quic or protocol == "vless" else ""
    alice_limits = " byte-quota=45" if byte_limits else alice_streams
    alice_connections = 2 if byte_limits and not is_quic else 1
    config.write_text(f'''schema-version 1
role "server"
workers {1 if protocol == "tuic" else 2}
control socket="{control}"
inbound "edge" type="{wire_protocol}" {{
 listen host="127.0.0.1" port={front}
 authentication {{ {users} }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
 {transport}
 user-limits {{ user "alice" connections={alice_connections}{alice_limits}; user "bob" connections=1{bob_streams}; }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')

    @contextlib.contextmanager
    def client(user):
        port = free_port()
        path = root / f"{protocol}-{port}.json"
        edge = {"type": wire_protocol, "server": "127.0.0.1", "server_port": front,
                "tls": {"enabled": True, "server_name": "localhost",
                        "certificate_path": str(root / "cert")}}
        if needs_uuid:
            edge["uuid"] = uuid_files[user]
        if wire_protocol != "vless":
            edge["password"] = user
        if is_quic or grpc:
            edge["tls"]["alpn"] = ["h3" if is_quic else "h2"]
        if grpc:
            edge["transport"] = {"type": "grpc", "service_name": "nexus.Service"}
        if udp_over_stream:
            edge["udp_relay_mode"] = "quic"
        path.write_text(json.dumps({
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [edge],
        }))
        with running(["sing-box", "run", "-c", path], port, path.with_suffix(".log")):
            yield port

    if byte_limits:
        with Origin(idle_timeout=10) as origin, Echo() as datagrams, nexus_process(binary, config) as proxy:
            with client("alice") as port, udp_client(port) as (udp, relay):
                with socks(port, 1, ("127.0.0.1", origin.port))[0] as tcp:
                    tcp.sendall(b"alice")
                    assert exact(tcp, 5) == b"alice"
                    datagram_request(udp, relay, datagrams.port, "127.0.0.1")
                    usage(binary, control, 0, "alice", upload=22, download=22, unconfirmed=0)
                    arrived = len(datagrams.received)
                    datagram_request(udp, relay, datagrams.port, "127.0.0.1", success=False)
                    assert len(datagrams.received) == arrived
                    usage(binary, control, 0, "alice", upload=22, download=22, byte_limit_denials=1)
                    if protocol == "tuic":
                        proxy.terminate()
                        try:
                            assert proxy.wait(4) == 0
                        except subprocess.TimeoutExpired:
                            proxy.kill()
                            proxy.communicate()
                            raise
        return

    if not is_quic:
        with nexus_process(binary, config), Origin(idle_timeout=10) as origin, Echo() as guarded:
            with client("alice") as port:
                with socks(port, 1, ("127.0.0.1", origin.port))[0] as tcp:
                    tcp.sendall(b"alice")
                    assert exact(tcp, 5) == b"alice"
                    usage(binary, control, 0, "alice", connections=1)
                    reject(port, guarded)
                    usage(binary, control, 0, "alice", connections=1, rejected_connections=1)
                    with client("bob") as other, socks(other, 1, ("127.0.0.1", origin.port))[0] as companion:
                        companion.sendall(b"bob")
                        assert exact(companion, 3) == b"bob"
                        usage(binary, control, 0, "bob", connections=1)
                usage(binary, control, 0, "alice", connections=0)
                with socks(port, 1, ("127.0.0.1", origin.port))[0] as recovered:
                    recovered.sendall(b"recovered")
                    assert exact(recovered, 9) == b"recovered"
                if protocol == "vless":
                    usage(binary, control, 0, "alice", connections=0)
                    with udp_client(port) as (udp, relay):
                        datagram_request(udp, relay, guarded.port, "127.0.0.1", success=False)
                        usage(binary, control, 0, "alice", rejected_streams=1)
                    with client("bob") as other, udp_client(other) as (udp, relay):
                        datagram_request(udp, relay, guarded.port, "127.0.0.1")
                        usage(binary, control, 0, "bob", streams=1)
        return

    with nexus_process(binary, config), Origin(idle_timeout=15) as origin, Echo() as datagrams:
        with client("alice") as port, udp_client(port) as (udp, relay):
            with socks(port, 1, ("127.0.0.1", origin.port))[0] as tcp:
                tcp.sendall(b"alice")
                assert exact(tcp, 5) == b"alice"
                usage(binary, control, 0, "alice", connections=1, streams=1)
                datagram_request(udp, relay, datagrams.port, "127.0.0.1", success=False)
                usage(binary, control, 0, "alice", rejected_streams=1)
                with client("bob") as other, udp_client(other) as (bob, bob_relay):
                    datagram_request(bob, bob_relay, datagrams.port, "127.0.0.1")
                    usage(binary, control, 0, "bob", connections=1, streams=1, rejected_connections=0)
                with client("alice") as other, udp_client(other) as (duplicate, duplicate_relay):
                    datagram_request(duplicate, duplicate_relay, datagrams.port, "127.0.0.1", success=False)
                    usage(binary, control, 0, "alice", connections=1, rejected_connections=1)
            usage(binary, control, 0, "alice", streams=0)
            datagram_request(udp, relay, datagrams.port, "127.0.0.1")
            usage(binary, control, 0, "alice", connections=1, streams=1)


if __name__ == "__main__":
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-user-limits-") as directory:
        root = Path(directory)
        for user in ("alice", "bob"):
            secret = root / user
            secret.write_text(user + "\n")
            secret.chmod(0o600)
        certificate(root)
        basic = {"mixed": mixed, "anytls": anytls}
        extended = ("shadowsocks", "trojan", "vless", "vless-grpc", "hysteria2", "tuic")
        selection = sys.argv[2:]
        if selection == ["--extended"]:
            selection = [*basic, *extended]
        if any(protocol in extended for protocol in selection):
            version = subprocess.check_output(["sing-box", "version"], text=True)
            assert f"Revision: {REVISION}" in version
        for protocol in selection or basic:
            if protocol in basic:
                basic[protocol](binary, root)
            elif protocol == "shadowsocks":
                shadowsocks(binary, root)
            elif protocol in extended:
                tls_peer(binary, root, protocol)
            else:
                raise ValueError(f"unknown fixture: {protocol}")
            print(f"{protocol} authenticated quotas and recovery passed", flush=True)
