#!/usr/bin/env python3
"""Check independent destination ports on one fixed-target UDP association."""
import argparse
import contextlib
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading

from detour_network import reserve
from dns_rule_support import nexus_process, udp_client
from tailscale_endpoint_network import eventually, ip, line, process
from tun_external_fd_network import prepare_network
from udp_bind_port_network import certificate
from vless_packetaddr_outbound_network import UUID

MARKER = "nx-fixed"
TARGETS = (
    (socket.AF_INET, "-4", "192.0.2.2", "198.51.100.1", 32),
    (socket.AF_INET6, "-6", "2001:db8:1::2", "2001:db8:2::1", 128),
)
PORTS = (18084, 18085)


def check_masque(binary, peer_binary):
    with tempfile.TemporaryDirectory(prefix="nexus-masque-targets-") as temp:
        root = Path(temp)
        certificate(root)
        token = root / "token"
        token.write_text("approved")
        token.chmod(0o600)
        with process([peer_binary, "serve-targets", root / "cert", root / "key"]) as peer:
            host, port = line(peer).decode().strip().rsplit(":", 1)
            front = reserve()
            config = root / "config.kdl"
            config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="masque" {{
    server host="{host}" port={port}
    authority "localhost"
    authentication {{ bearer-file "{token}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
routing {{ final "edge"; }}
''')
            with nexus_process(binary, config), udp_client(front) as (client, relay):
                destinations = ((1, "127.0.0.1", 53), (1, "127.0.0.1", 54), (4, "::1", 53))
                opened = []
                for round_, payload in enumerate((b"first", b"", b"again")):
                    for tag, host, destination in destinations:
                        family = socket.AF_INET6 if tag == 4 else socket.AF_INET
                        header = b"\0\0\0" + bytes([tag]) + socket.inet_pton(family, host) + struct.pack("!H", destination)
                        client.sendto(header + payload, relay)
                        if round_ == 0 and select.select([peer.stdout], [], [], .3)[0]:
                            opened.append(line(peer).decode().strip())
                        try:
                            response, _ = client.recvfrom(4096)
                        except TimeoutError as error:
                            raise AssertionError(f"no CONNECT-UDP reply for {host}:{destination}") from error
                        assert response == header + payload, (tag, destination, response)
                assert opened == [f"/.well-known/masque/udp/{host}/{port}/" for _, host, port in destinations], opened
    print("MASQUE SOCKS association exchanged three independent CONNECT-UDP targets and empty datagrams")


def check_tun(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-tun-fixed-targets-") as temp, \
            process(["unshare", "-n", "sleep", "25"]) as child:
        parent_ns = os.stat("/proc/self/ns/net").st_ino
        eventually(lambda: os.stat(f"/proc/{child.pid}/ns/net").st_ino != parent_ns)
        route = prepare_network(child.pid)
        root = Path(temp)
        certificate(root)
        uuid = root / "uuid"
        uuid.write_text(UUID)
        uuid.chmod(0o600)
        edge_port = reserve()
        edge = root / "edge.kdl"
        edge.write_text(f'''schema-version 1
role "server"
inbound "edge" type="vless" {{
    listen host="127.0.0.1" port={edge_port}
    authentication {{ user "test" uuid-file="{uuid}"; }}
    tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
        config = root / "config.kdl"
        config.write_text(f'''schema-version 1
role "client"
inbound "tun" type="tun" {{
    interface-name "{MARKER}"
    inet4-address "198.51.100.1/32"
    inet6-address "2001:db8:2::1/128"
    endpoint-independent-nat #true
}}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
    server host="127.0.0.1" port={edge_port}
    packet-encoding "fixed"
    authentication {{ uuid-file "{uuid}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
routing {{ final "edge"; }}
''')
        with process([*route, sys.executable, Path(__file__).resolve(), "--echo"]) as peer:
            assert line(peer) == b"ready\n"
            with nexus_process(binary, edge), nexus_process(binary, config):
                for family, flag, remote, local, prefix in TARGETS:
                    ip(flag, "route", "add", f"{remote}/{prefix}", "dev", MARKER, "table", "610")
                    ip(flag, "rule", "add", "from", f"{local}/{prefix}", "lookup", "610")
                    with socket.socket(family, socket.SOCK_DGRAM) as client:
                        client.bind((local, 0))
                        client.settimeout(3)
                        for payload in (b"first", b"", b"again"):
                            for port in PORTS:
                                client.sendto(payload, (remote, port))
                                response, addr = client.recvfrom(4096)
                                assert (response, addr[:2]) == (struct.pack("!H", port) + payload, (remote, port)), ((remote, port), response, addr)
    print("VLESS fixed UDP kept dual-stack endpoint-independent TUN destinations isolated by port")


def echo():
    def serve(sock, port):
        while True:
            data, addr = sock.recvfrom(2048)
            sock.sendto(struct.pack("!H", port) + data, addr)

    with contextlib.ExitStack() as stack:
        for family, _, remote, _, _ in TARGETS:
            for port in PORTS:
                sock = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
                sock.bind((remote, port))
                threading.Thread(target=serve, args=(sock, port), daemon=True).start()
        print("ready", flush=True)
        threading.Event().wait()


if __name__ == "__main__":
    if sys.argv[1] == "--echo":
        echo()
    elif sys.argv[1] == "--tun":
        check_tun(sys.argv[2])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("binary", type=Path)
        parser.add_argument("peer", type=Path)
        parser.add_argument("--masque-only", action="store_true")
        parser.add_argument("--tun-only", action="store_true")
        args = parser.parse_args()
        if not args.tun_only:
            check_masque(args.binary, args.peer)
        if not args.masque_only:
            subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--tun", args.binary],
                           check=True, timeout=30)
