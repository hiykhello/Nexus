#!/usr/bin/env python3
"""Exercise consistent snapshot updates with two veth pairs in one netns."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from detour_network import reserve, running


def ip(*args, command_list=None):
    return subprocess.check_output(["ip", *args], input=command_list, text=True, stderr=subprocess.PIPE)


def update(probe):
    probe.stdin.write("r\n")
    probe.stdin.flush()
    rows = []
    while line := probe.stdout.readline().strip():
        rows.append(line)
        if line.startswith("generation="):
            return rows
    raise AssertionError(f"snapshot update failed: {probe.wait()}, {rows}")


def topology():
    for link, peer, network in (("first", "peer-first", "192.0.2"), ("second", "peer-second", "198.51.100")):
        ip("link", "add", link, "type", "veth", "peer", "name", peer)
        ip("link", "set", link, "up")
        ip("link", "set", peer, "up")
        ip("addr", "add", f"{network}.2/24", "dev", link)
    ip("route", "add", "default", "via", "192.0.2.1", "dev", "first", "metric", "10")
    ip("route", "add", "default", "via", "198.51.100.1", "dev", "second", "metric", "20")
    ip("-6", "addr", "add", "2001:db8::2/64", "dev", "second", "nodad")
    ip("-6", "route", "add", "default", "via", "2001:db8::1", "dev", "second", "metric", "30")

def check(binary):
    ip("link", "set", "lo", "up")
    with subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as probe:
        try:
            assert probe.stdout.readline() == "ready generation=1\n"
            topology()
            first, second = (socket.if_nametoindex(name) for name in ("first", "second"))
            rows = update(probe)
            assert f"link {first} first veth true" in rows and f"link {second} second veth true" in rows, rows
            assert f"default 2 {first} 10" in rows and f"default 2 {second} 20" in rows, rows
            assert f"default 10 {second} 30" in rows and rows[-1].startswith("generation=2 baseline=1 addresses="), rows

            ip("route", "del", "default", "via", "192.0.2.1", "dev", "first", "metric", "10")
            ip("addr", "del", "192.0.2.2/24", "dev", "first")
            ip("link", "set", "first", "down")
            rows = update(probe)
            assert f"link {first} first veth false" in rows and f"default 2 {first} 10" not in rows, rows
            assert f"default 2 {second} 20" in rows and rows[-1].startswith("generation=3 baseline=1"), rows

            changes = "".join(f"route add 203.0.113.{i}/32 dev second\n" for i in range(1, 90))
            ip("-batch", "-", command_list=changes)
            rows = update(probe)
            assert rows[-1].startswith("generation=4 baseline=1"), rows
        finally:
            probe.stdin.close()
        assert probe.wait(timeout=4) == 0


def status(binary, control, previous, defaults):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        report = subprocess.check_output(
            [binary, "control", control, "status"], text=True, timeout=3
        )
        line = next(row for row in report.splitlines() if row.startswith("network-generation="))
        fields = dict(field.split("=") for field in line.split())
        generation = fields["network-generation"]
        if generation != "unknown" and int(generation) > previous and (
            fields["default-ipv4-routes"], fields["default-ipv6-routes"]
        ) == defaults:
            return int(generation)
        time.sleep(.02)
    raise AssertionError(report)


def check_proxy(binary):
    ip("link", "set", "lo", "up")
    with tempfile.TemporaryDirectory(prefix="nexus-network-view-") as directory:
        root = Path(directory)
        config = root / "proxy.kdl"
        control = root / "control.sock"
        front = reserve()
        config.write_text(f'''schema-version 1
role "client"
control socket="{control}"
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}; }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
        with running([binary, "run", "--config", str(config)], front, root / "proxy.log"):
            generation = status(binary, control, 0, ("0", "0"))
            topology()
            generation = status(binary, control, generation, ("2", "1"))
            ip("route", "del", "default", "via", "192.0.2.1", "dev", "first", "metric", "10")
            ip("-6", "route", "del", "default", "via", "2001:db8::1", "dev", "second", "metric", "30")
            ip("-6", "addr", "del", "2001:db8::2/64", "dev", "second")
            status(binary, control, generation, ("1", "0"))
    print("Production control status observed new network generations and dual-stack route withdrawal")

if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve())
    mode = sys.argv[2] if len(sys.argv) > 2 else "probe"
    namespace = os.stat("/proc/self/ns/net").st_ino
    if len(sys.argv) < 4:
        subprocess.run(["unshare", "-Urn", "--", sys.executable, __file__, binary, mode, str(namespace)], check=True)
    else:
        assert int(sys.argv[3]) != namespace
        if mode == "cli":
            check_proxy(binary)
        else:
            assert mode == "probe"
            check(binary)
            print("Two veth links, IPv4/IPv6 default routes, address removal and burst invalidation passed")
