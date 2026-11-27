#!/usr/bin/env python3
"""Verify routed TUN keeps old TCP and UDP policies across rules publication."""
import os
from proxy_listener_reload_network import reload as reload_listeners
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile

from dns_rule_support import exact
from tun_inbound_e2e import start_tcp_echo, start_udp_echo


def ip(*args):
    subprocess.run(["ip", *args], check=True, capture_output=True)


def udp_exchange(client, target, payload):
    client.sendto(payload, target)
    assert client.recvfrom(4096) == (payload, target)


def check(binary, root):
    rule = root / "route.kdl"
    rule.write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="203.0.113.0/24"\n')
    config = root / "proxy.kdl"
    config.write_text('''schema-version 1
role "client"
inbounds {
  tun "host" {
    interface-name "nx-reload"
    inet4-address "10.91.0.1/30"
    socket-mark 43
    endpoint-independent-nat #false
  }
}
outbound "direct" type="direct"
outbound "block" type="block"
routing {
  rulesets { "policy" path="route.kdl" format="kdl"; }
  rules { - kind="rule-set" value="policy" outbound="block"; }
  final "direct"
}
''')
    address = "198.51.100.10"
    destination = address + "/32"
    # Marked outbound sockets reach the echo peers on loopback. Unmarked
    # clients consult the TUN route before the local address table.
    ip("addr", "add", destination, "dev", "lo")
    ip("route", "add", "local", destination, "dev", "lo", "table", "100", "src", "127.0.0.1")
    ip("rule", "del", "priority", "0")
    ip("rule", "add", "priority", "1", "fwmark", "43", "lookup", "100")
    ip("rule", "add", "priority", "2", "to", destination, "table", "main")
    ip("rule", "add", "priority", "3", "lookup", "local")
    with subprocess.Popen(["stdbuf", "-oL", binary, "run", "--config", config],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0) as proxy:
        servers = []
        try:
            assert select.select([proxy.stdout], [], [], 6)[0] and b"TUN listening" in proxy.stdout.readline()
            ip("route", "add", destination, "dev", "nx-reload", "src", "10.91.0.1")
            tcp, tcp_port, tcp_stop = start_tcp_echo(address)
            udp, udp_port, udp_stop = start_udp_echo(address)
            servers.extend(((tcp, tcp_stop), (udp, udp_stop)))
            address = "198.51.100.10"
            target = (address, udp_port)
            with socket.create_connection((address, tcp_port), timeout=4) as stream, \
                 socket.socket(type=socket.SOCK_DGRAM) as previous, socket.socket(type=socket.SOCK_DGRAM) as current:
                previous.settimeout(3)
                udp_exchange(previous, target, b"before")
                stream.sendall(b"before")
                assert exact(stream, 6) == b"before"
                rule.write_text(f'schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="{address}/32"\n')
                assert reload_listeners(proxy) is None
                udp_exchange(previous, target, b"preserved")
                stream.sendall(b"preserved")
                assert exact(stream, 9) == b"preserved"
                current.sendto(b"blocked", target)
                assert not select.select([current], [], [], .3)[0]
                try:
                    with socket.create_connection((address, tcp_port), timeout=2) as fresh:
                        fresh.sendall(b"blocked")
                        assert fresh.recv(32) == b""
                except (ConnectionRefusedError, ConnectionResetError):
                    pass
        finally:
            proxy.terminate()
            _, errors = proxy.communicate(timeout=5)
            for server, stop in servers:
                stop.set()
                server.close()
            assert proxy.returncode == 0, errors
    assert subprocess.run(["ip", "link", "show", "nx-reload"], capture_output=True).returncode != 0


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve())
    namespace = os.stat("/proc/self/ns/net").st_ino
    if len(sys.argv) == 2:
        subprocess.run(["unshare", "-Urn", "--", sys.executable, __file__, binary, str(namespace)], check=True)
    else:
        assert int(sys.argv[2]) != namespace
        ip("link", "set", "lo", "up")
        with tempfile.TemporaryDirectory(prefix="nexus-tun-reload-") as directory:
            check(binary, Path(directory))
        print("Routed TUN retained established TCP/UDP policy and applied refreshed routes to new flows")
