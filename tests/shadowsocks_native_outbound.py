#!/usr/bin/env python3
"""Check native SS-2022 UDP with the fixed sing-box peer."""
import argparse
import json
from contextlib import ExitStack
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import threading
import time

from detour_network import running
from dns_rule_support import Echo, nexus_process, proxy_client, udp_client
from shadowsocks_identity_network import DatagramTap, material, transfer
from udp_bind_port_network import FAMILIES, REVISION, config, different_port, reserve_port, wire


class ReplyTap(DatagramTap):
    def __init__(self, port, outer_ipv6=False):
        super().__init__(port)
        self.outer_family = socket.AF_INET6 if outer_ipv6 else socket.AF_INET
        self.host = "::1" if outer_ipv6 else "127.0.0.1"
        self.wire = socket.socket(self.outer_family, socket.SOCK_DGRAM) if outer_ipv6 else self.socket
        if outer_ipv6:
            self.wire.bind((self.host, 0))
            self.port = self.wire.getsockname()[1]
        self.last_reply = None
        self.held = None
        self.sources = set()
        self.hold_next = threading.Event()
        self.observed = threading.Event()
        self.rebound = threading.Event()
        self.alternate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.alternate.bind(("127.0.0.1", 0))

    def __exit__(self, *args):
        try:
            super().__exit__(*args)
        finally:
            self.alternate.close()
            if self.wire != self.socket:
                self.wire.close()

    def relay(self):
        client = None
        while not self.stop.is_set():
            ready, _, _ = select.select(tuple({self.socket, self.wire, self.alternate}), (), (), .1)
            for wire_socket in ready:
                data, source = wire_socket.recvfrom(65535)
                if source == self.upstream:
                    if not client:
                        continue
                    if self.hold_next.is_set():
                        self.held = (data, client)
                        self.hold_next.clear()
                        self.observed.set()
                    else:
                        self.last_reply = (data, client)
                        self.wire.sendto(data, client)
                elif wire_socket == self.wire:
                    client = source
                    self.sources.add(source[:2])
                    uplink = self.alternate if self.rebound.is_set() else self.socket
                    uplink.sendto(data, self.upstream)

    def challenge(self):
        assert self.observed.wait(3), "peer sent no response to hold"
        assert self.last_reply is not None and self.held is not None
        reply, client = self.held
        changed = reply[:-1] + bytes([reply[-1] ^ 1])
        with socket.socket(self.outer_family, socket.SOCK_DGRAM) as wrong:
            wrong.sendto(reply, client)
        self.wire.sendto(changed, client)
        self.wire.sendto(*self.last_reply)

    def release(self):
        self.wire.sendto(*self.held)


def proxy_config(front, key, port, method, identity=None, *, lower=None, ordered=False, options='', inbound=None, host="127.0.0.1"):
    identity_option = f'identity-key-file "{identity}";' if identity else ''
    detour = 'detour "lower";' if lower else ''
    # Keep direct declared and put lower before edge to exercise dependency sorting.
    node = f'''{lower or ''}
outbound "edge" type="shadowsocks" {{
    server host="{host}" port={port}; method "{method}"; key-file "{key}";
    udp-mode "native"; {identity_option} {detour} {options}
}}'''
    return config(front, node=node, ordered=ordered, inbound=inbound)


def exchange(client, relay, family, port, payload):
    frame = wire(family, port, payload)
    client.sendto(frame, relay)
    answer, _ = client.recvfrom(65535)
    assert answer == frame, (family, payload[:20], len(answer))


def scenario(binary, root, kind, size, *, identity=False, layered=False, ordered=False, fixed_port=False,
             ss_inbound=False, outer_ipv6=False):
    method = f"2022-blake3-aes-{size*8}-gcm" if kind == "aes" else "2022-blake3-chacha20-poly1305"
    key_file, key = material(root, "user", 2, size)
    identity_file, identity_key = material(root, "identity", 1, size)
    peer_port = different_port()
    inbound = {"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": peer_port,
               "method": method, "password": identity_key if identity else key}
    if identity:
        inbound["users"] = [{"name": "alice", "password": key}]
    box_config = root / "peer.json"
    box_config.write_text(json.dumps({"inbounds": [inbound], "outbounds": [{"type": "direct"}]}))
    with ExitStack() as stack:
        stack.enter_context(running(["sing-box", "run", "-c", str(box_config)], peer_port, root / "box.log"))
        origin = stack.enter_context(Echo())
        tap = stack.enter_context(ReplyTap(peer_port, outer_ipv6))
        lower = None
        if layered:
            lower_port = different_port(peer_port, tap.port, origin.port)
            lower_key, _ = material(root, "lower", 10, 16)
            listener = f'''inbound "local" type="shadowsocks" {{
                listen host="127.0.0.1" port={lower_port};
                method "2022-blake3-aes-128-gcm"; key-file "{lower_key}";
            }}'''
            lower_config = root / "lower.kdl"
            lower_config.write_text(config(lower_port, inbound=listener).replace('role "client"', 'role "server"'))
            stack.enter_context(nexus_process(binary, lower_config))
            lower = f'''outbound "lower" type="shadowsocks" {{
                server host="127.0.0.1" port={lower_port}; method "2022-blake3-aes-128-gcm";
                key-file "{lower_key}"; udp-over-tcp "v2";
            }}'''
        front = different_port(peer_port, tap.port, origin.port)
        path = root / "client.kdl"
        source_port = None
        if fixed_port:
            reservation, source_port = stack.enter_context(reserve_port())
            reservation.close()
        listener = None
        if ss_inbound:
            inbound_key, inbound_psk = material(root, "inbound", 5, 16)
            listener = f'''inbound "local" type="shadowsocks" {{
                listen host="127.0.0.1" port={front};
                method "2022-blake3-aes-128-gcm"; key-file "{inbound_key}";
            }}'''
        path.write_text(proxy_config(front, key_file, tap.port, method, identity_file if identity else None,
                                     lower=lower, ordered=ordered,
                                     options=f"udp-bind-port {source_port};" if source_port else "", inbound=listener, host=tap.host))
        stack.enter_context(nexus_process(binary, path))
        entry = front
        if ss_inbound:
            entry = stack.enter_context(proxy_client(root, {
                "type": "shadowsocks", "server": "127.0.0.1", "server_port": front,
                "method": "2022-blake3-aes-128-gcm", "password": inbound_psk,
            }))
        client, relay = stack.enter_context(udp_client(entry))
        for family in FAMILIES:
            for payload in (b"", b"native-udp", bytes(range(256)) * 4):
                exchange(client, relay, family, origin.port, payload)
        held = wire(socket.AF_INET6, origin.port, b"held-response")
        tap.hold_next.set()
        client.sendto(held, relay)
        tap.challenge()
        client.settimeout(.25)
        try:
            raise AssertionError(("unexpected duplicate or forged datagram", client.recvfrom(65535)))
        except TimeoutError:
            pass
        client.settimeout(3)
        tap.release()
        assert client.recvfrom(65535)[0] == held
        if fixed_port:
            tap.rebound.set()
        exchange(client, relay, socket.AF_INET6, origin.port, b"after-replay")
        if source_port:
            assert tap.sources == {(tap.host, source_port)}, tap.sources

        # The mode selects only the UDP carrier. TCP still reaches the same
        # peer, using its real TCP port instead of the UDP tap port.
        if not layered:
            tcp_front = different_port(front, peer_port, tap.port, origin.port)
            tcp_path = root / "tcp.kdl"
            tcp_path.write_text(proxy_config(tcp_front, key_file, peer_port, method, identity_file if identity else None))
            with nexus_process(binary, tcp_path):
                transfer(tcp_front, origin.port)
        else:
            assert not origin.accepted
    print(f"{method}, identity={identity}, layered={layered}, ordered={ordered}, ss_inbound={ss_inbound}, outer_ipv6={outer_ipv6}: "
          "native IPv4/IPv6, empty, replay and forgery passed")


def lifecycle(binary, root):
    front = different_port()
    path = root / "lifecycle.kdl"
    key, _ = material(root, "key", 12, 16)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent_peer:
        silent_peer.bind(("127.0.0.1", 0))
        silent_peer.settimeout(3)
        path.write_text(proxy_config(front, key, silent_peer.getsockname()[1], "2022-blake3-aes-128-gcm"))
        with nexus_process(binary, path) as process, udp_client(front) as (client, relay):
            payload = wire(socket.AF_INET, 9, b"withheld")
            client.sendto(payload, relay)
            first, endpoint = silent_peer.recvfrom(2048)
            with udp_client(front) as (second, other_relay):
                second.sendto(payload, other_relay)
                other, other_endpoint = silent_peer.recvfrom(2048)
                assert endpoint != other_endpoint
                assert first[:16] != other[:16], "new association reused the first AES packet header"
                started = time.monotonic()
                process.terminate()
                assert process.wait(timeout=2) == 0 and time.monotonic() - started < 2
    print("Independent SS associations used different session headers and ports and stopped with both reads pending")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    options = parser.parse_args()
    binary = options.binary.resolve(strict=True)
    assert REVISION in subprocess.check_output(["sing-box", "version"], text=True)
    cases = (
        ("aes", 16, {"fixed_port": True}),
        ("aes", 32, {"ordered": True, "outer_ipv6": True}),
        ("aes", 16, {"identity": True, "ordered": True}),
        ("aes", 32, {"identity": True}),
        ("chacha", 32, {"ordered": True}),
        ("aes", 16, {"layered": True, "ordered": True}),
        ("aes", 16, {"ss_inbound": True, "ordered": True}),
        ("aes", 16, {"ss_inbound": True}),
    )
    for kind, size, settings in cases:
        with tempfile.TemporaryDirectory(prefix="nexus-native-ss-") as directory:
            scenario(binary, Path(directory), kind, size, **settings)
    with tempfile.TemporaryDirectory(prefix="nexus-native-ss-stop-") as directory:
        lifecycle(binary, Path(directory))


if __name__ == "__main__":
    main()
