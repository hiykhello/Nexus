#!/usr/bin/env python3
"""Observe an expired address answer and the single shared background refresh."""
import argparse
import concurrent.futures
import contextlib
import socket
import struct
import tempfile
import threading
import time
from pathlib import Path

from anytls_network import Origin
from dns_rule_support import DnsPeer, exact, free_port, nexus_process, question, stream_request, udp_client, wire_name


class ExpiringPeer(DnsPeer):
    ttl = 2
    authenticated = False

    def reply(self, packet, transport):
        response = bytearray(super().reply(packet, transport))
        if self.authenticated:
            response[3] |= 0x20
        _, _, end = question(response)
        struct.pack_into("!I", response, end + 6, self.ttl)
        return response


def verify(binary, host, ipv6):
    name = "optimistic.test"
    with tempfile.TemporaryDirectory(prefix="nexus-dns-optimistic-") as directory, ExpiringPeer(ipv6) as peer:
        config = Path(directory) / "proxy.kdl"
        front = free_port()
        config.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
dns {{
  server "upstream" type="udp" host="{host}" port={peer.port}
  final "upstream"
  strategy "ipv4_only"
  optimistic-cache-seconds 5
}}
routing {{ default-outbound "direct"; }}
''')
        gate = threading.Event()
        with nexus_process(binary, config), Origin(expected=4) as origin:
            stream_request(front, origin.port, name)
            assert peer.count(name, 1) == 1, peer.seen
            peer.gates[(name, 1)] = gate
            try:
                time.sleep(1.2)
                started = time.monotonic()
                stream_request(front, origin.port, name)
                stream_request(front, origin.port, name)
                assert time.monotonic() - started < 1, "stale callers waited for the gated refresh"
                end = time.monotonic() + 1
                while peer.count(name, 1) < 2 and time.monotonic() < end:
                    time.sleep(.01)
                assert peer.count(name, 1) == 2, peer.seen
                peer.ttl = 30
                gate.set()
                time.sleep(.2)
                stream_request(front, origin.port, name)
                assert peer.count(name, 1) == 2, peer.seen
                origin.wait()
            finally:
                gate.set()
    print(f"{host}: stale answer served and two workers shared one refresh")


def ask_message(port, name, identifier, tcp=False, hijack=None):
    wire = struct.pack("!6H", identifier, 0x0100, 1, 0, 0, 0) + wire_name(name) + struct.pack("!HH", 1, 1)
    if hijack:
        client, relay = hijack
        prefix = b"\0\0\0\1" + socket.inet_aton("127.0.0.1") + struct.pack("!H", port)
        client.sendto(prefix + wire, relay)
        response = client.recv(4096)
        assert response.startswith(prefix), response
        response = response[len(prefix):]
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.connect(("127.0.0.1", port))
            if tcp:
                client.sendall(struct.pack("!H", len(wire)) + wire)
                response = exact(client, int.from_bytes(exact(client, 2), "big"))
            else:
                client.send(wire)
                response = client.recv(4096)
    assert int.from_bytes(response[:2], "big") == identifier and not response[3] & 15, response
    _, _, end = question(response)
    return bool(response[3] & 0x20), struct.unpack_from("!I", response, end + 6)[0]


def verify_listener(binary, host, ipv6, intercept=False):
    name = "http-cache-optimistic.test"
    with tempfile.TemporaryDirectory(prefix="nexus-dns-message-stale-") as directory, ExpiringPeer(ipv6) as peer:
        config = Path(directory) / "proxy.kdl"
        front, listener = free_port(), free_port()
        while listener == front:
            listener = free_port()
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
dns {{
  listen host="127.0.0.1" port={listener}
  server "upstream" type="udp" host="{host}" port={peer.port}
  final "upstream"
  optimistic-cache-seconds 5
}}
routing {{ default-outbound "direct"; }}
''')
        if intercept:
            rule = config.parent / "dns.kdl"
            rule.write_text(f'schema-version 2\nkind "predicate"\nrule type="port" value="{listener}"\n')
            content = config.read_text().replace(f'  listen host="127.0.0.1" port={listener}\n', '')
            content = content.replace('routing { default-outbound "direct"; }', '''routing {
  rule-set "dns" path="dns.kdl" format="kdl"
  tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {
    rule action="hijack-dns" rule-set="dns"
    rule action="route" outbound="direct"
  }
  default-outbound "direct"
}''')
            config.write_text(content)
        peer.authenticated = True
        peer.ttl = 1
        gate = threading.Event()
        with nexus_process(binary, config), contextlib.ExitStack() as sockets:
            ingress = sockets.enter_context(udp_client(front)) if intercept else None
            if not intercept:
                shared = "shared-wire.test"
                arrived = threading.Event()
                peer.gates[(shared, 1)] = arrived
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    a = pool.submit(ask_message,listener,shared,701)
                    b = pool.submit(ask_message,listener,shared,702,True)
                    try:
                        end = time.monotonic() + 1
                        while not peer.count(shared, 1) and time.monotonic() < end:
                            time.sleep(.01)
                        assert peer.count(shared, 1) == 1
                        time.sleep(.15)
                    finally:
                        arrived.set()
                    assert a.result(timeout=3) == (True,1)
                    assert b.result(timeout=3) == (True,1)
                time.sleep(.1)
                assert peer.count(shared, 1) == 1, peer.seen
            assert ask_message(listener, name, 801, hijack=ingress) == (True, 1)
            peer.gates[(name, 1)] = gate
            try:
                time.sleep(1.2)
                start = time.monotonic()
                for identifier, tcp in ((802, False), (803, True), (804, False)):
                    authenticated, ttl = ask_message(listener, name, identifier, tcp, ingress)
                    assert not authenticated and 1 <= ttl <= 5, (authenticated, ttl)
                assert time.monotonic() - start < 1
                end = time.monotonic() + 1
                while peer.count(name, 1) < 2 and time.monotonic() < end:
                    time.sleep(.01)
                assert peer.count(name, 1) == 2, peer.seen
                peer.ttl = 30
                gate.set()
                time.sleep(.2)
                authenticated, ttl = ask_message(listener, name, 805, True, ingress)
                assert authenticated and ttl >= 28, (authenticated, ttl)
                assert peer.count(name, 1) == 2, peer.seen
            finally:
                gate.set()
    ingress_name = "hijacked UDP" if intercept else "dedicated UDP/TCP"
    print(f"{host}: {ingress_name} shared DNS work, bounded stale TTL and cleared AD")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nexus", type=Path)
    args = parser.parse_args()
    binary = args.nexus.resolve(strict=True)
    verify(binary, "127.0.0.1", False)
    verify(binary, "::1", True)
    verify_listener(binary, "127.0.0.1", False)
    verify_listener(binary, "::1", True)
    verify_listener(binary, "127.0.0.1", False, intercept=True)


if __name__ == "__main__":
    main()
