#!/usr/bin/env python3
"""Exercise production FakeIP publication and ordinary/ordered TCP recovery."""
import os
import select
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

from detour_network import running
from dns_rule_support import DnsPeer, Echo, datagram_request, dns_request, exact, free_port, udp_client


def request(front, host, port, accepted=True):
    with socket.create_connection(("127.0.0.1", front), timeout=3) as client:
        client.sendall(b"\x05\x01\x00")
        assert exact(client, 2) == b"\x05\0"
        address = socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        client.sendall(b"\x05\x01\0" + bytes([1 if len(address)==4 else 4]) + address + struct.pack("!H", port))
        first=client.recv(1)
        if not first and not accepted:
            return
        reply = first + exact(client, 3)
        assert (reply[1] == 0) == accepted, reply
        exact(client, 6 if reply[3] == 1 else 18)
        if accepted:
            client.sendall(b"lease")
            assert exact(client, 5) == b"lease"


def alias_datagram(client, relay, target, port, allowed=True):
    address = socket.inet_pton(socket.AF_INET6 if ":" in target else socket.AF_INET, target)
    prefix = bytes([0, 0, 0, 1 if len(address) == 4 else 4]) + address + struct.pack("!H", port)
    message = prefix + b"alias datagram"
    client.sendto(message, relay)
    if allowed:
        client.settimeout(3)
        assert client.recv(128) == message
    else:
        assert not select.select([client], [], [], .25)[0], target


binary = str(Path(sys.argv[1]).resolve(strict=True))
with tempfile.TemporaryDirectory() as directory, DnsPeer() as dns, Echo() as echo:
    root = Path(directory)
    state = root / "state"
    state.mkdir(mode=0o700)
    for name, size in (("instance.id", 16), ("history.key", 32)):
        path = state / name
        path.touch(mode=0o600)
        path.write_bytes(os.urandom(size))
    config = root / "proxy.kdl"
    front, dns_port = free_port(), free_port()
    (root / "target.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="blocked.test"\n')
    text = f"""schema-version 1
role "client"
log {{ privacy "verbose"; }}
workers 2
inbounds {{ mixed "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}; }}
outbounds {{ direct "direct"; }}
dns {{
    listen host="127.0.0.1" port={dns_port}
    server "protected" type="udp" host="127.0.0.1" port={dns.port}
    final "protected"
    strategy "ipv4_only"
    rule domain="denied.test" action="reject"
    fake-ip server="protected" ipv4-pool="198.18.0.0/29" ipv6-pool="fd15:4231::/96" ttl-seconds=2 state-directory="{state}"
}}
"""
    legacy = 'routing { default-outbound "direct"; }\n'
    ordered = """routing {
  rule-set "denied" path="target.kdl" format="kdl"
  tcp-program sniff-timeout-ms=100 unknown="pause" udp=#true {
    rule action="resolve"
    rule action="reject" rule-set="denied" domain-source="fakeip"
    rule action="route" outbound="direct"
  }
  default-outbound "direct"
}
"""
    config.write_text(text.replace('ttl-seconds=2', 'ttl-seconds=2 initialize=#true') + legacy)
    command = [binary, "run", "--config", str(config)]
    with running(command, front, root / "first.log"):
        assert dns_request(dns_port, "origin.test") == (2, None), "fresh pool skipped the quarantine"
        assert dns_request(dns_port, "denied.test") == (5, None)
        time.sleep(12.2)
        status, address = dns_request(dns_port, "origin.test")
        assert not status and address == "198.18.0.1", (status, address)
        assert dns_request(dns_port, "origin.test", socket.SOCK_STREAM, 0x3421) == (0, address)
        assert not dns.count("origin.test", 1), dns.seen
        request(front, address, echo.port)
        assert dns.count("origin.test", 1), dns.seen
        request(front, "198.18.0.7", echo.port, False)
        status, ipv6 = dns_request(dns_port, "origin.test", socket.SOCK_STREAM, kind=28)
        assert (status, ipv6) == (0, "fd15:4231::c612:1")
        request(front, ipv6, echo.port)
        request(front, "fd15:4231::ffff", echo.port, False)
        with udp_client(front) as (client, relay):
            datagram_request(client, relay, echo.port, "udp.test")
            alias_datagram(client, relay, address, echo.port)
            alias_datagram(client, relay, ipv6, echo.port)
            alias_datagram(client, relay, "fd15:4231::ffff", echo.port, False)
    for replacement in ("fd15:9876::/96", None):
        requested=text.replace('ipv6-pool="fd15:4231::/96" ',
            f'ipv6-pool="{replacement}" ' if replacement else '')
        config.write_text(requested + ordered)
        failed=subprocess.run(command, capture_output=True, text=True, timeout=5)
        assert failed.returncode and "FakeIP history" in failed.stderr, failed.stderr
    config.write_text(text + ordered)
    with running(command, front, root / "restart.log"):
        request(front, address, echo.port, False)
        request(front, ipv6, echo.port, False)
        assert dns_request(dns_port, "origin.test") == (2, None), "restart skipped the quarantine"
        time.sleep(12.2)
        status, address = dns_request(dns_port, "origin.test")
        assert not status and address == "198.18.0.1"
        request(front, address, echo.port)
        status, blocked = dns_request(dns_port, "blocked.test")
        assert not status and blocked != address
        request(front, blocked, echo.port, False)
        with udp_client(front) as (client, relay):
            datagram_request(client, relay, echo.port, "ordered.test")
            alias_datagram(client, relay, address, echo.port)
            alias_datagram(client, relay, ipv6, echo.port)
            alias_datagram(client, relay, blocked, echo.port, False)
print("FakeIP A/AAAA publication, history quarantine, legacy/ordered TCP/UDP and original UDP sources passed")
