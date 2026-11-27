#!/usr/bin/env python3
"""Verify routed TUN delivers both directions of TCP half-close."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading

from detour_network import exact
from dns_rule_support import nexus_process
from tailscale_endpoint_network import eventually, ip, line, process
from tun_external_fd_network import prepare_network

DEVICE = "nx-fin"
PORT = 18081
TARGETS = (
    (socket.AF_INET, "-4", "192.0.2.2", "198.51.100.1", 32),
    (socket.AF_INET6, "-6", "2001:db8:1::2", "2001:db8:2::1", 128),
)
REQUEST = b"client request after FIN"
RESPONSE = bytes(range(256)) * 513 + b"end of stream"


def origin():
    def serve(listener):
        with listener:
            for peer_first in (False, True):
                stream, _ = listener.accept()
                with stream:
                    stream.settimeout(6)
                    if not peer_first:
                        stream.sendall(b"origin ready")
                        stream.shutdown(socket.SHUT_WR)
                    assert exact(stream, len(REQUEST)) == REQUEST
                    assert stream.recv(1) == b""
                    if peer_first:
                        stream.sendall(RESPONSE)
                        stream.shutdown(socket.SHUT_WR)
            print("origin drained", flush=True)

    threads = []
    for family, _, destination, _, _ in TARGETS:
        listener = socket.socket(family)
        listener.settimeout(10)
        listener.bind((destination, PORT))
        listener.listen(2)
        thread = threading.Thread(target=serve, args=(listener,))
        threads.append(thread)
        thread.start()
    print("ready", flush=True)
    for thread in threads:
        thread.join()


def exchange():
    for family, _, destination, local, _ in TARGETS:
        for client_first in (False, True):
            with socket.socket(family) as stream:
                stream.settimeout(4)
                stream.bind((local, 0))
                stream.connect((destination, PORT))
                if not client_first:
                    assert exact(stream, len(b"origin ready")) == b"origin ready"
                    try:
                        assert stream.recv(1) == b""
                    except TimeoutError as error:
                        raise AssertionError(f"server FIN did not reach TUN client for {family.name}") from error
                stream.sendall(REQUEST)
                stream.shutdown(socket.SHUT_WR)
                if client_first:
                    assert exact(stream, len(RESPONSE)) == RESPONSE
                    assert stream.recv(1) == b""


def run(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-tun-fin-") as temp, \
            process(["unshare", "-n", "sleep", "30"]) as child:
        parent_ns = os.stat("/proc/self/ns/net").st_ino
        eventually(lambda: os.stat(f"/proc/{child.pid}/ns/net").st_ino != parent_ns)
        route = prepare_network(child.pid)
        config = Path(temp) / "config.kdl"
        config.write_text(f'''schema-version 1
role "client"
inbound "tun" type="tun" {{
    interface-name "{DEVICE}"
    inet4-address "198.51.100.1/32"
    inet6-address "2001:db8:2::1/128"
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
        with process([*route, sys.executable, Path(__file__).resolve(), "--origin"]) as peer:
            assert line(peer) == b"ready\n"
            with nexus_process(binary, config):
                for _, flag, destination, local, prefix in TARGETS:
                    ip(flag, "route", "add", f"{destination}/{prefix}", "dev", DEVICE, "table", "610")
                    ip(flag, "rule", "add", "from", f"{local}/{prefix}", "lookup", "610")
                exchange()
            for _ in TARGETS:
                assert line(peer) == b"origin drained\n"
    print("Routed TUN passed server-first FIN, client-first FIN and large buffered replies on IPv4 and IPv6")


if __name__ == "__main__":
    if sys.argv[1] == "--origin":
        origin()
    elif sys.argv[1] == "--namespace":
        run(sys.argv[2])
    else:
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--namespace", sys.argv[1]],
                       check=True, timeout=35)
