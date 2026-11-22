"""Verify FakeIP reply identity over real Trojan UDP and Shadowsocks UoT streams."""

import base64
import contextlib
import ipaddress
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from connect_traffic_stats import trojan_server
from detour_network import reserve, running
from dns_rule_support import DnsPeer, dns_request, udp_client

NAMES = ("one.trojan.test", "two.trojan.test", "one.uot.test", "two.uot.test")


@contextlib.contextmanager
def ss_server(binary, root):
    port = reserve()
    key = root / "ss.key"
    key.write_bytes(base64.b64encode(bytes(range(16))))
    key.chmod(0o600)
    config = root / "ss.kdl"
    config.write_text(f'''schema-version 1
role "server"
inbounds {{ shadowsocks "node" {{
    listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{key}";
}}; }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
    with running([binary, "run", "--config", str(config)], port, root / "ss.log"):
        yield f'''shadowsocks "uot" {{
    server host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{key}";
    udp-over-tcp "v2";
}}'''


@contextlib.contextmanager
def vless_server(binary, root):
    port = reserve()
    uuid = root / "uuid"
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n")
    uuid.chmod(0o600)
    cert, key = root / "cert", root / "key"
    config = root / "vless.kdl"
    config.write_text(f'''schema-version 1
role "server"
inbounds {{
    vless "node" {{
        listen host="127.0.0.1" port={port}
        authentication {{ user "test" uuid-file="{uuid}"; }}
        tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
    }}
}}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
    with running([binary, "run", "--config", str(config)], port, root / "vless.log"):
        yield f'''vless "xudp" {{
    server host="127.0.0.1" port={port}
    authentication {{ uuid-file "{uuid}"; }}
    tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}
}}'''


def configure(root, front, dns_port, peer, trojan, other, outbound, ordered):
    state = root / "state"
    state.mkdir(mode=0o700)
    for name, size in (("instance.id", 16), ("history.key", 32)):
        path = state / name
        path.touch(mode=0o600)
        path.write_bytes(os.urandom(size))
    for scheme in ("trojan", "uot"):
        (root / f"{scheme}.kdl").write_text(
            f'schema-version 2\nkind "predicate"\nrule type="domain-suffix" value="{scheme}.test"\n')
    route = f'''tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{
        rule action="route" rule-set="trojan" domain-source="fakeip" outbound="edge"
        rule action="route" rule-set="uot" domain-source="fakeip" outbound="{outbound}"
        rule action="reject"
    }}''' if ordered else f'''rule kind="rule-set" value="trojan" outbound="edge"
    rule kind="rule-set" value="uot" outbound="{outbound}"'''
    config = root / "proxy.kdl"
    config.write_text(f'''schema-version 1
role "client"
workers 2
control socket="{root / "proxy.sock"}"
inbounds {{ mixed "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}; }}
outbounds {{
    direct "direct"
{trojan}
{other}
}}
dns {{
    listen host="127.0.0.1" port={dns_port}
    server "protected" type="udp" host="127.0.0.1" port={peer.port}
    final "protected"
    strategy "prefer_ipv4"
    fake-ip server="protected" ipv4-pool="198.18.0.0/29" ipv6-pool="fd15:4231::/96" ttl-seconds=2 state-directory="{state}" initialize=#true
}}
routing {{
    rule-set "trojan" path="trojan.kdl" format="kdl"
    rule-set "uot" path="uot.kdl" format="kdl"
    {route}
    default-outbound "direct"
}}
''')
    return config


def fake_frame(address, port):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return bytes((0, 0, 0, 4 if family == socket.AF_INET6 else 1)) + socket.inet_pton(family, address) + struct.pack("!H", port)


def expect_aliases(client, relay, origin, aliases):
    frames = {payload: fake_frame(alias, origin.getsockname()[1]) for payload, alias in zip((b"", b"second"), aliases)}
    for payload, prefix in frames.items():
        client.sendto(prefix + payload, relay)
    remotes = {}
    for _ in frames:
        payload, source = origin.recvfrom(256)
        assert payload in frames and payload not in remotes, (payload, remotes)
        remotes[payload] = source
    assert len(set(remotes.values())) == 2, remotes
    with socket.socket(origin.family, socket.SOCK_DGRAM) as unrelated:
        for source in remotes.values():
            unrelated.sendto(b"unexpected", source)
        assert not select.select([client], [], [], .25)[0], "reply from the wrong UDP port was accepted"
    for payload in (b"second", b""):
        origin.sendto(payload, remotes[payload])
    assert {client.recvfrom(256)[0], client.recvfrom(256)[0]} == {
        prefix + payload for payload, prefix in frames.items()
    }


def get_aliases(port):
    deadline = time.monotonic() + 16
    while True:
        status, address = dns_request(port, NAMES[0])
        if status == 0:
            assert address
            break
        assert status == 2 and time.monotonic() < deadline, (status, address)
        time.sleep(.2)
    aliases = [address]
    for name, kind in zip(NAMES[1:], (1, 28, 28)):
        status, alias = dns_request(port, name, kind=kind)
        assert status == 0 and alias, (name, status, alias)
        aliases.append(alias)
    assert len(set(aliases)) == len(NAMES)
    return aliases


def verify(binary, root, peer, ipv4, ipv6, trojan, other, outbound, ordered):
    front, dns_port = reserve(), reserve()
    config = configure(root, front, dns_port, peer, trojan, other, outbound, ordered)
    mode = "ordered" if ordered else "indexed"
    command = [binary, "run", "--config", str(config)]
    control = [binary, "control", str(root / "proxy.sock")]
    with running(command, front, root / "proxy.log") as process:
        aliases = get_aliases(dns_port)
        with udp_client(front) as (client, relay):
            for origin, targets, actual in ((ipv4, aliases[:2], "edge"), (ipv6, aliases[2:], outbound)):
                expect_aliases(client, relay, origin, targets)
                row = subprocess.check_output([*control, "connections", "0"], timeout=4, text=True)
                assert f"outbound={actual}" in row and f"route-mode={mode}" in row, row
            time.sleep(12.3)
            for name in ("new1.test", "new2.test"):
                status, address = dns_request(dns_port, name)
                assert status == 0 and address, (name, status, address)
            assert dns_request(dns_port, "pinned.test") == (2, None)
        deadline = time.monotonic() + 4
        while True:
            status, address = dns_request(dns_port, "unpinned.trojan.test")
            if status == 0:
                former = set(aliases[:2]) | {
                    str(ipaddress.IPv4Address(int(ipaddress.IPv6Address(alias)) & 0xffffffff)) for alias in aliases[2:]
                }
                assert address in former, (address, former)
                break
            assert status == 2 and time.monotonic() < deadline, (status, address)
            time.sleep(.025)
        with udp_client(front) as (client, relay):
            status, late = dns_request(dns_port, "unpinned.trojan.test")
            assert status == 0
            client.sendto(fake_frame(late, ipv4.getsockname()[1]) + b"stopping", relay)
            assert ipv4.recvfrom(256)[0] == b"stopping"
            process.terminate()
            assert process.wait(timeout=6) == 0
        print(f"{mode}: dual-stack FakeIP Trojan and {outbound} preserved alias replies, rejected unrelated ports, released leases, and stopped with an active tunnel")


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    with (tempfile.TemporaryDirectory(prefix="nexus-fakeip-udp-") as directory,
          DnsPeer() as peer,
          socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ipv4,
          socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as ipv6):
        root = Path(directory)
        peer.no_data.update((name, kind) for name, kind in zip(NAMES, (28, 28, 1, 1)))
        ipv4.bind(("127.0.0.1", 0))
        ipv6.bind(("::1", 0))
        for origin in (ipv4, ipv6):
            origin.settimeout(5)
        xudp = "--xudp" in sys.argv[2:]
        second = vless_server if xudp else ss_server
        with trojan_server(binary, root) as trojan, second(binary, root) as other:
            verify(binary, root, peer, ipv4, ipv6, trojan, other, "xudp" if xudp else "uot", "--ordered" in sys.argv[2:])
