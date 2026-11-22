"""Check DNS request and FakeIP lease isolation across a live policy publication."""

import concurrent.futures
import os
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import tempfile
import threading
import time

from detour_network import reserve, running
from dns_rule_support import DnsPeer, dns_request, question, udp_client


class AddressPeer(DnsPeer):
    def __init__(self, address):
        super().__init__()
        self.addresses = {}
        self.default_address = address

    def reply(self, packet, transport):
        wire = super().reply(packet, transport)
        name, kind, _ = question(packet)
        if wire and kind == 1 and name in ("cache.test", "slow.test"):
            return wire[:-4] + socket.inet_aton(self.addresses.get(name, self.default_address))
        return wire


def poll(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "condition did not become observable"
        time.sleep(.025)


def write_rules(path, name):
    text = f'schema-version 2\nkind "predicate"\nrule type="domain" value="{name}"\n'
    pending = path.with_suffix(".new")
    pending.write_text(text)
    pending.replace(path)


def config_text(root, front, port, primary, secondary):
    state = root / "state"
    state.mkdir(mode=0o700)
    for name, size in (("instance.id", 16), ("history.key", 32)):
        file = state / name
        file.touch(mode=0o600)
        file.write_bytes(os.urandom(size))
    return f'''schema-version 1
role "client"
workers 2
inbounds {{ mixed "front" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}; }}
outbounds {{ direct "direct"; }}
dns {{
    listen host="127.0.0.1" port={port}
    server "fake" type="udp" host="127.0.0.1" port={primary.port}
    server "primary" type="udp" host="127.0.0.1" port={primary.port}
    server "secondary" type="udp" host="127.0.0.1" port={secondary.port}
    final "fake"
    strategy "ipv4_only"
    rule-set "switch" path="dns.kdl" format="kdl"
    rule rule-set="switch" server="secondary"
    rule domain="slow.test" server="primary"
    rule domain="cache.test" server="primary"
    fake-ip server="fake" ipv4-pool="198.18.0.0/29" ttl-seconds=2 state-directory="{state}" initialize=#true
}}
routing {{ default-outbound "direct"; }}
'''


def alias_query(port):
    deadline = time.monotonic() + 16
    while True:
        status, address = dns_request(port, "alias.test")
        if status == 0:
            assert address
            return address
        assert status == 2 and time.monotonic() < deadline, (status, address)
        time.sleep(.2)


def visit(association, origin, alias, forwarded=True):
    client, relay = association
    prefix = b"\x00\x00\x00\x01" + socket.inet_aton(alias) + struct.pack("!H", origin.getsockname()[1])
    client.sendto(prefix + b"view probe", relay)
    if not forwarded:
        assert not select.select([origin, client], [], [], .25)[0], alias
        return
    payload, source = origin.recvfrom(128)
    assert payload == b"view probe"
    origin.sendto(payload, source)
    assert client.recvfrom(128)[0] == prefix + payload


def verify(binary, root, origin, primary, secondary):
    front, port = reserve(), reserve()
    config = root / "proxy.kdl"
    rules = root / "dns.kdl"
    initial = config_text(root, front, port, primary, secondary)
    config.write_text(initial)
    write_rules(rules, "unrelated.test")
    command = [binary, "run", "--config", str(config)]
    log = root / "proxy.log"
    with running(command, front, log) as process, concurrent.futures.ThreadPoolExecutor(1) as pool:
        old = alias_query(port)
        assert dns_request(port, "cache.test") == (0, "127.0.0.2")
        assert dns_request(port, "cache.test", socket.SOCK_STREAM) == (0, "127.0.0.2")
        assert primary.count("cache.test", 1) == 1
        with udp_client(front) as old_flow:
            visit(old_flow, origin, old)
            gate = threading.Event()
            primary.gates["slow.test", 1] = gate
            previous = pool.submit(dns_request, port, "slow.test")
            try:
                poll(lambda: primary.count("slow.test", 1) == 1)
                write_rules(rules, "slow.test")
                process.send_signal(signal.SIGHUP)
                poll(lambda: "traffic rules reloaded" in log.read_text())
                assert dns_request(port, "slow.test", socket.SOCK_STREAM) == (0, "127.0.0.3")
            finally:
                gate.set()
            assert previous.result(timeout=4) == (0, "127.0.0.2")
            primary.addresses["cache.test"] = "127.0.0.4"
            assert dns_request(port, "cache.test") == (0, "127.0.0.4")
            assert primary.count("cache.test", 1) == 2
            status, new = dns_request(port, "alias.test", socket.SOCK_STREAM)
            assert status == 0 and new != old, (old, status, new)
            visit(old_flow, origin, old)
            visit(old_flow, origin, new, False)
            with udp_client(front) as new_flow:
                visit(new_flow, origin, old, False)
                visit(new_flow, origin, new)
    config.write_text(initial.replace(" initialize=#true", ""))
    with running(command, front, root / "restart.log"):
        assert dns_request(port, "alias.test") == (2, None)
        with udp_client(front) as fresh:
            visit(fresh, origin, old, False)
            visit(fresh, origin, new, False)
        released = alias_query(port)
        with udp_client(front) as current:
            visit(current, origin, released)
    print("DNS reload separated same-name aliases and cached answers, retained old in-flight upstream, and preserved restart quarantine")


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    with (tempfile.TemporaryDirectory(prefix="nexus-fakeip-view-") as directory,
          AddressPeer("127.0.0.2") as primary,
          AddressPeer("127.0.0.3") as secondary,
          socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin):
        origin.bind(("127.0.0.1", 0))
        origin.settimeout(4)
        verify(binary, Path(directory), origin, primary, secondary)
