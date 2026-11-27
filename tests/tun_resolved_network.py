#!/usr/bin/env python3
"""Exercise the supervised routed TUN DNS stub inside the private resolved fixture."""
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile

from dns_rule_support import DnsPeer, question, wire_name
from tailscale_endpoint_network import eventually, ip, line

DEVICE = "nx-resolved"
LOCAL4 = "198.18.0.1"
LOCAL6 = "2001:db8:10::1"


def resolved_address(name, kind):
    wire = struct.pack("!6H", 123, 0x100, 1, 0, 0, 0) + wire_name(name) + struct.pack("!HH", kind, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(4)
        client.sendto(wire, ("127.0.0.53", 53))
        response, source = client.recvfrom(4096)
        assert source == ("127.0.0.53", 53)
    identifier, flags, questions, answers = struct.unpack_from("!4H", response)
    assert identifier == 123 and flags & 15 == 0 and questions == 1 and answers == 1, response.hex()
    size = 4 if kind == 1 else 16
    return socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6, response[-size:])


def state():
    return ip("-4", "rule", "show"), ip("-6", "rule", "show")


def no_device():
    return subprocess.run(["ip", "link", "show", "dev", DEVICE], capture_output=True).returncode != 0


class Upstream(DnsPeer):
    def reply(self, wire, transport):
        result = super().reply(wire, transport)
        if result is None:
            return None
        if question(wire)[1] == 28:
            return result[:-16] + socket.inet_pton(socket.AF_INET6, "2001:db8::93")
        return result[:-4] + socket.inet_pton(socket.AF_INET, "192.0.2.93")


def check_peer(binary):
    ip("link", "add", "nx-physical", "type", "dummy")
    ip("link", "set", "dev", "nx-physical", "up")
    ip("address", "add", "192.0.2.1/24", "dev", "nx-physical")
    ip("-6", "address", "add", "2001:db8:1::1/64", "dev", "nx-physical", "nodad")
    ip("-4", "route", "add", "default", "dev", "nx-physical")
    ip("-6", "route", "add", "default", "dev", "nx-physical")
    baseline = state()
    with tempfile.TemporaryDirectory(prefix="nexus-tun-resolved-") as temp, Upstream() as peer:
        path = Path(temp) / "config.kdl"
        config = f'''schema-version 1
role "client"
inbound "tun" type="tun" {{{{
    interface-name "{DEVICE}"
    inet4-address "{LOCAL4}/32"
    inet6-address "{LOCAL6}/128"
    auto-route #true
    strict-route #true
    host-dns "resolved"
}}}}
outbound "direct" type="direct"
dns {{{{
    listen host="{{listen}}" port={{port}}
    server "upstream" type="udp" host="127.0.0.1" port={peer.port}
    final "upstream"
}}}}
routing {{{{ final "direct"; }}}}
'''
        for listen, port in (("127.0.0.2", 53), (LOCAL4, 5300)):
            path.write_text(config.format(listen=listen, port=port))
            rejected = subprocess.run([binary, "run", "--config", path], capture_output=True, text=True, timeout=6)
            assert rejected.returncode and "DNS listener on port 53" in rejected.stderr, rejected.stderr
            assert state() == baseline and no_device()
        path.write_text(config.format(listen=LOCAL4, port=53))
        args = ["stdbuf", "-oL", binary, "run", "--config", path]
        for listen, crash, expected in ((LOCAL4, True, "192.0.2.93"), (LOCAL6, False, "2001:db8::93")):
            path.write_text(config.format(listen=listen, port=53))
            with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as tunnel:
                try:
                    inspect_stub(tunnel,listen,crash,expected,peer)
                finally:
                    if tunnel.poll() is None:
                        tunnel.terminate()
                    try:
                        tunnel.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        tunnel.kill()
                        tunnel.communicate(timeout=3)
                        raise
            eventually(lambda: no_device() and state() == baseline)
            status = subprocess.run(["resolvectl", "dns"], capture_output=True, text=True, check=True, timeout=4).stdout
            assert DEVICE not in status
        print("Supervised routed TUN published private resolved IPv4/IPv6 stubs, forwarded queries and cleaned up after proxy SIGKILL")


def inspect_stub(tunnel,listen,crash,expected,peer):
    assert line(tunnel).startswith(f"TUN listening on {DEVICE}".encode())
    kind = 1 if listen == LOCAL4 else 28
    name = "stub-ipv4.example" if kind == 1 else "stub-ipv6.example"
    assert resolved_address(name, kind) == expected, peer.seen
    assert (name, kind, "udp") in peer.seen
    # Hold the owning process separately so a SIGKILL of the proxy
    # proves the surviving owner finishes its cleanup.
    owners = Path(f"/proc/{tunnel.pid}/task/{tunnel.pid}/children").read_text().split()
    assert len(owners) == 1, owners
    if crash:
        tunnel.send_signal(signal.SIGKILL)
        assert tunnel.wait(timeout=4) == -signal.SIGKILL
    else:
        tunnel.terminate()
        assert tunnel.wait(timeout=8) == 0


if __name__ == "__main__":
    check_peer(Path(sys.argv[1]).resolve(strict=True))
