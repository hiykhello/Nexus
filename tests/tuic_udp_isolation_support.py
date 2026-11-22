"""Drive concurrent SOCKS UDP associations over a shared TUIC connection."""
import contextlib
import socket
import struct

from dns_rule_support import udp_client


def exercise_udp_isolation(front, fingerprint):
    with contextlib.ExitStack() as stack:
        endpoints = []
        for family, address, tag in ((socket.AF_INET, "127.0.0.1", 1), (socket.AF_INET6, "::1", 4)):
            origin = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
            origin.bind((address, 0))
            origin.settimeout(3)
            header = b"\0\0\0" + bytes([tag]) + socket.inet_pton(family, address)
            header += struct.pack("!H", origin.getsockname()[1])
            endpoints.append((origin, header))
        with udp_client(front) as (a, relay_a), udp_client(front) as (b, relay_b):
            for round_ in range(6):
                pending = []
                for connection, (client, relay) in enumerate(((a, relay_a), (b, relay_b))):
                    index = (round_ + connection) % len(endpoints)
                    origin, header = endpoints[index]
                    payload = bytes((round_, connection)) if round_ != 4 else b""
                    client.sendto(header + payload, relay)
                    try:
                        incoming, peer = origin.recvfrom(65535)
                    except TimeoutError as error:
                        raise AssertionError(f"missing {fingerprint} TUIC request round={round_} association={connection} family={origin.family}") from error
                    assert incoming == payload, (round_, connection, incoming)
                    pending.append((origin, peer, client, header, payload))
                for origin, peer, client, header, payload in reversed(pending):
                    origin.sendto(payload, peer)
                    try:
                        received, _ = client.recvfrom(4096)
                    except TimeoutError as error:
                        raise AssertionError(f"lost TUIC reply for association in round {round_}") from error
                    assert received == header + payload, (round_, received)
            # Stopping with two suspended readers also exercises wakeup and drain.
    print(f"TUIC {fingerprint} kept concurrent dual-stack SOCKS UDP associations and empty replies isolated")
