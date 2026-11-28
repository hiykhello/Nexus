#!/usr/bin/env python3
"""Same-association DNS interception and target policy checks on SOCKS5 and TUN."""
import contextlib
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile

from connect_traffic_stats import trojan_server
from dns_batch93c_network import listener, query
from dns_rule_support import DnsPeer, bind_same_port, free_port, nexus_process, udp_client
from routing_batch93b_network import peer_link
from tailscale_endpoint_network import ip, line, process

STUN = bytes.fromhex("000100002112a44200112233445566778899aabb")
BIND = "192.0.2.11"
TARGET = "192.0.2.2"
BLOCKED = "192.0.2.3"


def configure(root, front, dns, port, tun, ordered, trojan):
    path = root / "route.kdl"
    (root / "ip.kdl").write_text(f'schema-version 2\nkind "predicate"\nip-cidr "{BLOCKED}/32"\n')
    (root / "proxy.kdl").write_text(f'schema-version 2\nkind "predicate"\nport {port}\n')
    (root / "explicit-dns.kdl").write_text('schema-version 2\nkind "predicate"\nport 5354\n')
    inbound = '''inbound "tun" type="tun" {
    interface-name "nx-packet"
    inet4-address "198.51.100.1/32"
    auto-route #true
    strict-route #true
    include-routing-mark 0x2a
}
''' if tun else listener(front)
    routing = '''
    tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {
        rule action="hijack-dns" rule-set="explicit-dns"
        rule action="hijack-dns"
        rule action="reject" rule-set="deny"
        rule action="route" rule-set="tunnel" outbound="edge"
        rule action="route" outbound="direct"
    }
''' if ordered else '''
    rules {
        - rule-set="deny" to="block"
        - rule-set="tunnel" to="edge"
    }
'''
    explicit = '        explicit-dns path="explicit-dns.kdl" format="kdl"' if ordered else ""
    path.write_text(f'''schema-version 1
role "client"
log {{ privacy "verbose"; }}
{inbound}
outbounds {{
    direct "direct" {{ inet4-bind-address "{BIND if tun else '127.0.0.2'}"; }}
    block "block"
    {trojan}
}}
dns {{
    server "up" type="udp" host="127.0.0.1" port={dns}
    disable-cache #true
    final "up"
}}
routing {{
    rulesets {{
        deny path="ip.kdl" format="kdl"
        tunnel path="proxy.kdl" format="kdl"
{explicit}
    }}
    {routing}
    final "direct"
}}
''')
    return path


def exchange(client, relay, target, payload, reply=True):
    header = b"\0\0\0\1" + socket.inet_aton(target[0]) + struct.pack("!H", target[1])
    client.sendto(header + payload if relay else payload, relay or target)
    client.settimeout(3 if reply else .35)
    try:
        data, peer = client.recvfrom(2048)
    except TimeoutError:
        if reply:
            raise
        return None
    assert reply, (target, data)
    if relay:
        assert peer == relay and data.startswith(header), (peer, data)
        return data[len(header):]
    assert peer == target, (target, peer)
    return data


def assertions(sock, relay, address, blocked, direct_src, proxy_src, direct_port, proxy_port, ordered):
    if ordered:
        dns = query("hijacked.test")
        assert exchange(sock, relay, (address, 53), dns)[:2] == dns[:2]
        # Same socket and source port, including a DNS-shaped datagram that is
        # transparently relayed to an ordinary destination.
        assert exchange(sock, relay, (address, direct_port), STUN) == direct_src + b":" + STUN
        assert exchange(sock, relay, (address, direct_port), dns) == direct_src + b":" + dns
        assert exchange(sock, relay, (address, 5354), dns)[:2] == dns[:2]
    assert exchange(sock, relay, (address, direct_port), b"first direct") == direct_src + b":first direct"
    assert exchange(sock, relay, (blocked, direct_port), b"blocked", reply=False) is None
    assert exchange(sock, relay, (address, proxy_port), b"new port") == proxy_src + b":new port"
    assert exchange(sock, relay, (address, direct_port), b"still direct") == direct_src + b":still direct"


PEERS = """
from contextlib import ExitStack
import select, socket, sys
a, b, p, q = sys.argv[1:]
with ExitStack() as stack:
    sockets = []
    for ip, port in ((a, p), (b, p), (a, q)):
        sock = stack.enter_context(socket.socket(type=socket.SOCK_DGRAM))
        sock.bind((ip, int(port)))
        sockets.append(sock)
    print("ready", flush=True)
    while True:
        ready, _, _ = select.select([sys.stdin, *sockets], [], [], 5)
        if sys.stdin in ready:
            break
        for sock in ready:
            data, source = sock.recvfrom(2048)
            sock.sendto(source[0].encode()+b":"+data, source)
"""


def run(binary, root, tun, ordered):
    with contextlib.ExitStack() as stack:
        if tun:
            namespace = stack.enter_context(peer_link("nxedge", "nxpeer", "02:00:00:00:00:31"))
            ip("addr", "add", "192.0.2.1/24", "dev", "nxedge")
            ip("addr", "add", BIND + "/24", "dev", "nxedge")
            for address in (TARGET, BLOCKED):
                ip("addr", "add", address + "/24", "dev", "nxpeer", prefix=namespace)
            address, denied, direct, proxy = TARGET, BLOCKED, b"192.0.2.1", BIND.encode()
        else:
            namespace = ()
            ip("addr", "add", BLOCKED + "/32", "dev", "lo")
            address, denied, direct, proxy = "127.0.0.1", BLOCKED, b"127.0.0.2", b"127.0.0.1"
        def port():
            selected, (spare,) = bind_same_port(((socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1"),))
            spare.close()
            assert selected not in (53, 5354)
            return selected

        direct_port, proxy_port = port(), port()
        while proxy_port == direct_port:
            proxy_port = port()
        peer = stack.enter_context(process([*namespace, sys.executable, "-u", "-c", PEERS, address, denied,
                                            str(direct_port), str(proxy_port)], stdin=subprocess.PIPE))
        assert line(peer) == b"ready\n"
        dns = stack.enter_context(DnsPeer())
        edge = stack.enter_context(trojan_server(binary, root, BIND if tun else None))
        front = free_port()
        config = configure(root, front, dns.port, proxy_port, tun, ordered, edge)
        stack.enter_context(nexus_process(binary, config))
        if tun:
            client = stack.enter_context(socket.socket(type=socket.SOCK_DGRAM))
            client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x2a)
            relay = None
        else:
            client, relay = stack.enter_context(udp_client(front))
        assertions(client, relay, address, denied, direct, proxy, direct_port, proxy_port, ordered)
        assert dns.count("hijacked.test", 1) == (2 if ordered else 0), dns.seen
    print(f"{'TUN' if tun else 'SOCKS5'} {'ordered' if ordered else 'indexed'}: "
          "one UDP source, direct then blocked IP then Trojan destination port, plus DNS/STUN boundary where enabled")


if __name__ == "__main__":
    cli, mode = str(Path(sys.argv[1]).resolve()), sys.argv[2]
    if len(sys.argv) == 3:
        raise SystemExit(subprocess.call(["unshare", "-Urn", sys.executable, __file__, cli, mode, "isolated"]))
    ip("link", "set", "lo", "up")
    with tempfile.TemporaryDirectory(prefix="nexus-93c-udp-") as work:
        run(cli, Path(work), mode.startswith("tun"), mode.endswith("ordered"))
