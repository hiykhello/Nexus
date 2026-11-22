#!/usr/bin/env python3
"""Test the production CONNECT-IP server in isolated Linux namespaces."""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

from masque_ip_tun import capture, wait_until
from tailscale_endpoint_network import eventually, ip, line, process
from tun_inbound_e2e import tcp_echo_check
from udp_bind_port_network import certificate


def test_server(binary, peer, remote):
    local = "192.0.2.1"
    port = 18443
    ip("link", "set", "lo", "up")
    ip("link", "set", "lo", "up", prefix=remote)
    ip("link", "add", "nx-outer", "type", "veth", "peer", "name", "nx-remote")
    ip("link", "set", "nx-remote", "netns", remote[2])
    ip("address", "add", f"{local}/24", "dev", "nx-outer")
    ip("address", "add", "192.0.2.2/24", "dev", "nx-remote", prefix=remote)
    ip("link", "set", "nx-outer", "up")
    ip("link", "set", "nx-remote", "up", prefix=remote)
    ip("address", "add", "198.51.100.99/32", "dev", "lo")
    with tempfile.TemporaryDirectory(prefix="nexus-masque-ip-server-") as folder:
        root = Path(folder)
        certificate(root)
        bearer = root / "bearer"
        bearer.write_text("approved\n")
        bearer.chmod(0o600)
        server = root / "server.kdl"
        server.write_text(f'''schema-version 1
role "server"
inbound "edge" type="masque" {{
    listen host="{local}" port={port}
    authority "localhost"
    authentication {{ bearer-file "{bearer}"; }}
    tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
    connect-ip {{
        interface-name "nx-ip-server"
        local-address "198.51.100.42"
        local-address "2001:db8:60::42"
        client-address "10.60.0.2"
        client-address "fd60::2"
        allow-ip "198.51.100.42/32"
        allow-ip "2001:db8:60::42/128"
    }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        client = root / "client.kdl"
        client.write_text(f'''schema-version 1
role "client"
inbound "tun" type="tun" {{
    interface-name "nx-masque-ip"
    connect-ip-outbound "edge"
    connect-ip-route "198.51.100.42/32"
    connect-ip-route "2001:db8:60::42/128"
}}
outbound "direct" type="direct"
outbound "edge" type="masque" {{
    mode "connect-ip"
    server host="{local}" port={port}
    authority "localhost"
    authentication {{ bearer-file "{bearer}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
    idle-timeout-ms 3000
}}
routing {{ default-outbound "direct"; }}
''')
        echo = Path(__file__).with_name("tailscale_endpoint_network.py")
        launch = ["stdbuf", "-oL", binary, "run", "--config", server]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as denied, \
                process([sys.executable, echo, "--echo"], stdin=subprocess.PIPE) as target, process(launch) as serving:
            denied.bind(("0.0.0.0", 18082))
            denied.settimeout(.2)
            if line(target) != b"ready\n" or b"MASQUE listening" not in line(serving):
                raise RuntimeError("CONNECT-IP server or target failed to start")
            subprocess.run([*remote, peer, "check-server", root / "cert", f"{local}:{port}"], check=True, timeout=10)
            try:
                packet, source = denied.recvfrom(2048)
            except TimeoutError:
                pass
            else:
                raise RuntimeError(f"unauthorized CONNECT-IP packet reached server from {source}: {packet!r}")
            wait_until(serving, lambda: capture("ip", "link", "show", "nx-ip-server").returncode != 0)
            with process([*remote, binary, "run", "--config", client]) as connecting:
                wait_until(connecting, lambda: capture(*remote, "ip", "link", "show", "nx-masque-ip").returncode == 0)
                for host in ("198.51.100.42", "2001:db8:60::42"):
                    command = "-6" if ":" in host else "-4"
                    wait_until(connecting, lambda: "dev nx-masque-ip" in capture(*remote, "ip", command, "route", "get", host).stdout)
                subprocess.run([*remote, sys.executable, __file__, "traffic"], check=True, timeout=14)
                serving.terminate()
                serving.wait(timeout=5)
                if serving.returncode:
                    raise RuntimeError(f"CONNECT-IP server stop returned {serving.returncode}")
                eventually(lambda: all(
                    capture(*remote, "ip", family, "route", "get", host).returncode != 0
                    for family, host in (("-4", "198.51.100.42"), ("-6", "2001:db8:60::42"))
                ), timeout=2)
            if capture("ip", "link", "show", "nx-ip-server").returncode == 0:
                raise RuntimeError("CONNECT-IP server left its TUN device")
            for host in ("10.60.0.2", "fd60::2"):
                if capture("ip", "route", "get", host).returncode == 0:
                    raise RuntimeError(f"CONNECT-IP client route survived shutdown: {host}")
    print("CONNECT-IP server verified independent HTTP/3 authorization and traffic, dual-stack TCP, route and device cleanup")


if __name__ == "__main__":
    if sys.argv[1:] == ["traffic"]:
        for family, host in ((socket.AF_INET, "198.51.100.42"), (socket.AF_INET6, "2001:db8:60::42")):
            tcp_echo_check(family, host, 18080, b"nexus-connect-ip" * 90)
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("binary", type=Path)
        parser.add_argument("peer", type=Path)
        parser.add_argument("--outer", type=int, nargs=2)
        args = parser.parse_args()
        binary, peer = (str(path.resolve(strict=True)) for path in (args.binary, args.peer))
        inode = tuple(os.stat(f"/proc/self/ns/{name}").st_ino for name in ("net", "user"))
        if args.outer:
            if any(outside == inside for outside, inside in zip(args.outer, inode)):
                raise RuntimeError("fixture requires a private network and user namespace")
            with process(["unshare", "-n", "sleep", "40"]) as namespace:
                eventually(lambda: os.stat(f"/proc/{namespace.pid}/ns/net").st_ino != inode[0])
                test_server(binary, peer, ("nsenter", "-t", str(namespace.pid), "-n"))
        else:
            subprocess.run(["unshare", "-Urn", sys.executable, __file__, binary, peer, "--outer", *map(str, inode)],
                           check=True, timeout=45)
