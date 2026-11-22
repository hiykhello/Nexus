"""Isolated routed TUN tests for UDP source filtering and ICMP rejection."""
import select
import socket
import struct
import subprocess
import sys

from tailscale_endpoint_network import ip, line, process


def check_udp_policy(nexus_bin, root, prefix, baseline):
    ip("address", "add", "192.0.2.3/24", "dev", "nxpeer", prefix=prefix)
    ip("-6", "address", "add", "2001:db8:1::3/64", "dev", "nxpeer", "nodad", prefix=prefix)
    reply_peer = """import socket
import threading

def sockets(family, host, other):
    result = [socket.socket(family, socket.SOCK_DGRAM) for _ in range(3)]
    for endpoint, address in zip(result, (host, host, other)):
        endpoint.bind((address, 0))
    return result

def serve(sockets):
    first, *alternates = sockets
    while True:
        data, address = first.recvfrom(4096)
        if len(data) > 1500:
            assert data == b'fragment' * 250
            first.sendto(b'reassembled', address)
            continue
        assert data == b'filter'
        for sender, name in zip(sockets, (b'original', b'other-port', b'other-address')):
            sender.sendto(name, address)

v4 = sockets(socket.AF_INET, '192.0.2.2', '192.0.2.3')
v6 = sockets(socket.AF_INET6, '2001:db8:1::2', '2001:db8:1::3')
print(v4[0].getsockname()[1], v6[0].getsockname()[1], flush=True)
thread = threading.Thread(target=serve, args=(v4,), daemon=True)
thread.start()
serve(v6)
"""
    (root / "udp-reject.kdl").write_text(
        'schema-version 1\nkind "predicate"\n'
        'rule type="ip-cidr" value="198.51.100.85/32"\n'
        'rule type="ip-cidr" value="2001:db8:3::85/128"\n')
    routing = '''routing {
    rule-set "reject" path="udp-reject.kdl" format="kdl"
    tcp-program sniff-timeout-ms=60 unknown="skip" udp=#true {
        rule action="reject" rule-set="reject"
        rule action="route" outbound="direct"
    }
    default-outbound "direct"
}
'''
    config = root / "udp-policy.kdl"
    with process([*prefix, sys.executable, "-c", reply_peer]) as peer:
        port4, port6 = map(int, line(peer).split())
        for mode, expected in (
            ("address-port-dependent", {b"original"}),
            ("address-dependent", {b"original", b"other-port"}),
            ("endpoint-independent", {b"original", b"other-port", b"other-address"}),
        ):
            settings = f'strict-route #true\n    udp-filtering "{mode}"\n    udp-reject "icmp"'
            config.write_text(baseline[:baseline.index("routing {")].replace("strict-route #true", settings) + routing)
            with process(["stdbuf", "-oL", nexus_bin, "run", "--config", config]) as nexus:
                assert b"TUN listening on nx-strict" in line(nexus)
                for family, address, port in (
                    (socket.AF_INET, "192.0.2.2", port4),
                    (socket.AF_INET6, "2001:db8:1::2", port6),
                ):
                    with socket.socket(family, socket.SOCK_DGRAM) as client:
                        client.settimeout(.4)
                        client.sendto(b"filter", (address, port))
                        received = set()
                        while True:
                            try:
                                received.add(client.recv(256))
                            except TimeoutError:
                                break
                    assert received == expected, (mode, family, received)

                if mode == "address-port-dependent":
                    check_udp_rejection()
                    for family, address, port, level, option in (
                        (socket.AF_INET, "192.0.2.2", port4, socket.IPPROTO_IP, 10),
                        (socket.AF_INET6, "2001:db8:1::2", port6, socket.IPPROTO_IPV6, 23),
                    ):
                        with socket.socket(family, socket.SOCK_DGRAM) as client:
                            client.setsockopt(level, option, 0)
                            client.settimeout(3)
                            client.sendto(b"fragment" * 250, (address, port))
                            assert client.recv(256) == b"reassembled", family
    print("TUN UDP reply filtering and ICMP rejection passed for both families")


def check_udp_rejection():
    for family, destination, level, option, origin, kind, code in (
        (socket.AF_INET, "198.51.100.85", socket.IPPROTO_IP, 11, 2, 3, 13),
        (socket.AF_INET6, "2001:db8:3::85", socket.IPPROTO_IPV6, 25, 3, 1, 1),
    ):
        with socket.socket(family, socket.SOCK_DGRAM) as client:
            client.setsockopt(level, option, 1)
            client.connect((destination, 9999))
            client.send(b"administratively blocked")
            errors = select.poll()
            errors.register(client, select.POLLERR)
            assert errors.poll(2500), family
            _, controls, _, _ = client.recvmsg(256, 256, socket.MSG_ERRQUEUE)
            extended = [data for group, field, data in controls if (group, field) == (level, option)]
            assert len(extended) == 1, controls
            assert struct.unpack_from("=IBBBB", extended[0])[1:4] == (origin, kind, code), controls
