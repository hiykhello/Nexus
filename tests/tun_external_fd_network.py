#!/usr/bin/env python3
"""Use a host-configured TUN through the production CLI in a Linux netns."""
import fcntl
import os
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from detour_network import exact
from tailscale_endpoint_network import eventually, ip, line, process

DEVICE = "nx-owned"
TARGETS = (
    (socket.AF_INET, "-4", "192.0.2.2", "198.51.100.1", 32),
    (socket.AF_INET6, "-6", "2001:db8:1::2", "2001:db8:2::1", 128),
)


def config(path, inbound):
    path.write_text(f'''schema-version 1
role "client"
inbound "host-tun" type="tun" {{
    {inbound}
    mtu 1400
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    return path


def rejected(cli, config_path, expected, fds=()):
    attempt = subprocess.run([cli, "run", "--config", config_path], pass_fds=fds,
                             capture_output=True, text=True, timeout=5)
    assert attempt.returncode and expected in attempt.stderr, attempt.stderr


def echo_through_tun():
    for family, _, remote, local, _ in TARGETS:
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(family, kind) as client:
                client.settimeout(5)
                client.bind((local, 0))
                client.connect((remote, 18080))
                payload = f"external TUN {family} {kind}".encode()
                client.sendall(payload)
                answer = exact(client, len(payload)) if kind == socket.SOCK_STREAM else client.recv(256)
                assert answer == payload, (remote, kind, answer)


def device_open():
    return subprocess.run(["ip", "link", "show", "dev", DEVICE], capture_output=True).returncode == 0


def prepare_network(peer):
    ip("link", "set", "lo", "up")
    ip("link", "add", "nxphysical", "type", "veth", "peer", "name", "nxpeer")
    ip("link", "set", "nxpeer", "netns", str(peer))
    route = ("nsenter", "-t", str(peer), "-n")
    ip("link", "set", "nxphysical", "up")
    ip("link", "set", "nxpeer", "up", prefix=route)
    ip("address", "add", "192.0.2.1/24", "dev", "nxphysical")
    ip("address", "add", "192.0.2.2/24", "dev", "nxpeer", prefix=route)
    ip("-6", "address", "add", "2001:db8:1::1/64", "dev", "nxphysical", "nodad")
    ip("-6", "address", "add", "2001:db8:1::2/64", "dev", "nxpeer", "nodad", prefix=route)
    return route


def namespace_run(cli):
    with tempfile.TemporaryDirectory(prefix="nexus-external-tun-") as temp, \
            process(["unshare", "-n", "sleep", "45"]) as nested:
        current = os.stat("/proc/self/ns/net").st_ino
        eventually(lambda: os.stat(f"/proc/{nested.pid}/ns/net").st_ino != current)
        route = prepare_network(nested.pid)
        path = Path(temp) / "config.kdl"
        fds = os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC
        fd = os.open("/dev/net/tun", fds)
        try:
            # TUNSETIFF with IFF_TUN | IFF_NO_PI.
            fcntl.ioctl(fd, 0x400454ca, struct.pack("16sH22x", DEVICE.encode(), 0x1001))
            ip("link", "set", DEVICE, "mtu", "1400", "up")
            for family, flag, remote, local, prefix in TARGETS:
                nodad = ("nodad",) if family == socket.AF_INET6 else ()
                ip(flag, "address", "add", f"{local}/{prefix}", "dev", DEVICE, *nodad)
                ip(flag, "route", "add", f"{remote}/{prefix}", "dev", DEVICE, "table", "610")
                ip(flag, "rule", "add", "from", f"{local}/{prefix}", "lookup", "610")

            rejected(cli, config(path, "device-fd 2"), "device-fd")
            rejected(cli, config(path, f'device-fd {fd}\n    auto-route #true'), "host-managed", (fd,))
            rejected(cli, config(path, f'device-fd {fd}\n    interface-name "nx-other"'),
                     "matching interface name", (fd,))
            invalid = os.open("/dev/null", fds)
            try:
                rejected(cli, config(path, f"device-fd {invalid}"),
                         "attaching TUN device-fd", (invalid,))
            finally:
                os.close(invalid)

            expected = ip("-j", "address", "show", "dev", DEVICE)
            echo = Path(__file__).with_name("tailscale_endpoint_network.py")
            with process([*route, sys.executable, echo, "--echo"], stdin=subprocess.PIPE) as peer:
                assert line(peer) == b"ready\n"
                for ownership in ("borrow", "borrow", "adopt"):
                    options = f'device-fd {fd}' if ownership == "borrow" else f'device-fd {fd} ownership="adopt"'
                    args = [cli, "run", "--config", config(path, options)]
                    with process(["stdbuf", "-oL", *args], pass_fds=(fd,)) as nexus:
                        assert f"TUN listening on {DEVICE}".encode() in line(nexus)
                        proc_fds = Path(f"/proc/{nexus.pid}/fd")
                        found = sum(os.readlink(item) == "/dev/net/tun" for item in proc_fds.iterdir())
                        assert found == (2 if ownership == "borrow" else 1), (ownership, found)
                        assert ip("-j", "address", "show", "dev", DEVICE) == expected
                        if ownership == "adopt":
                            os.close(fd)
                            fd = None
                        echo_through_tun()
                    assert device_open() == (ownership == "borrow")
        finally:
            if fd is not None:
                os.close(fd)
    print("Host-owned TUN IPv4/IPv6 TCP and UDP, borrowed restart and adopted cleanup passed")


if __name__ == "__main__":
    if sys.argv[1] == "--namespace":
        namespace_run(sys.argv[2])
    else:
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--namespace", sys.argv[1]],
                       check=True, timeout=45)
