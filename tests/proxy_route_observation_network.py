"""Compare active TCP route decisions with the CLI explain replay across a selector publication."""

import contextlib
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from connect_traffic_stats import trojan_server
from detour_network import exact, reserve, running


def command(binary, *args):
    return subprocess.check_output([binary, *map(str, args)], timeout=5, text=True)


def connect(front, destination):
    peer = socket.create_connection(("127.0.0.1", front), timeout=5)
    try:
        authority = f"127.0.0.1:{destination}"
        peer.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            header += exact(peer, 1)
        assert header.startswith(b"HTTP/1.1 200 "), header
        return peer
    except BaseException:
        peer.close()
        raise


def inspect(binary, control, peers, mode, protocol="http-connect"):
    rows = {}
    for line in command(binary, "control", control, "connections", 0).splitlines():
        row = dict(field.split("=", 1) for field in shlex.split(line))
        if row.get("protocol") == protocol:
            rows[int(row["source-port"])] = row
    matched = []
    for peer in peers:
        row = rows[peer.getsockname()[1]]
        assert row["route-mode"] == mode and row["route-rule"] == "1", row
        matched.append(row)
    return matched


def udp_associate(front, stack):
    control = stack.enter_context(socket.create_connection(("127.0.0.1", front), timeout=5))
    control.sendall(b"\x05\x01\x00")
    assert exact(control, 2) == b"\x05\x00"
    control.sendall(b"\x05\x03\x00\x01" + bytes(6))
    reply = exact(control, 10)
    assert reply[:4] == b"\x05\x00\x00\x01", reply
    relay = (socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:])[0])
    packet = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    packet.settimeout(5)
    return control, relay, packet


def udp_roundtrip(association, origin, payload):
    _, relay, packet = association
    host, port = origin.getsockname()
    frame = b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port)
    packet.sendto(frame + payload, relay)
    received, peer = origin.recvfrom(256)
    assert received == payload, received
    origin.sendto(received, peer)
    assert packet.recvfrom(256)[0] == frame + payload


def verify(binary, root, origin, udp, edge, ordered):
    target = origin.getsockname()[1]
    front = reserve()
    control = root / "control.sock"
    config = root / "proxy.kdl"
    (root / "target.kdl").write_text(
        f'schema-version 2\nkind "predicate"\nrule type="port" value="{target}"\n')
    rule = (
        'tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true { '
        'rule action="route" rule-set="target" outbound="primary"; }'
        if ordered else 'rules { - kind="rule-set" value="target" outbound="primary"; }'
    )
    source = f"""schema-version 1
role "client"
workers 2
control socket="{control}"
inbounds {{ mixed "entry" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}; }}
outbounds {{
    direct "local"
    {edge}
    selector "primary" {{ member "local"; member "edge"; selected "local"; }}
}}
routing {{
    rule-set "target" path="target.kdl" format="kdl"
    {rule}
    default-outbound "local"
}}
"""
    config.write_text(source)
    mode = "ordered" if ordered else "indexed"
    with running([binary, "run", "--config", str(config)], front, root / "run.log"), contextlib.ExitStack() as stack:
        def open_group():
            group = []
            for _ in range(8):
                client = stack.enter_context(connect(front, target))
                remote = stack.enter_context(origin.accept()[0])
                remote.settimeout(5)
                group.append((client, remote))
            return group

        old = open_group()
        old_udp = udp_associate(front, stack)
        udp_roundtrip(old_udp, udp, b"generation 1")
        old_rows = inspect(binary, control, [peer for peer, _ in old], mode)
        assert {(row["route-generation"], row["outbound"], row["path"]) for row in old_rows} == {
            ("1", "local", "direct")
        }, old_rows
        replay = command(binary, "rule", "explain", config, "entry", "tcp", f"127.0.0.1:{target}")
        assert "rule=1 " in replay and "outbound=local" in replay, replay
        command(binary, "control", control, "select", "primary", "edge")
        new = open_group()
        new_udp = udp_associate(front, stack)
        udp_roundtrip(old_udp, udp, b"generation 1 after publication")
        udp_roundtrip(new_udp, udp, b"generation 2")
        new_rows = inspect(binary, control, [peer for peer, _ in new], mode)
        assert {(row["route-generation"], row["outbound"], row["path"]) for row in new_rows} == {
            ("2", "edge", "tunnel")
        }, new_rows
        assert inspect(binary, control, [peer for peer, _ in old], mode) == old_rows
        old_route, new_route = inspect(binary, control, [old_udp[0], new_udp[0]], mode, "socks5-udp")
        assert (old_route["route-generation"], old_route["outbound"]) == ("1", "local"), old_route
        assert (new_route["route-generation"], new_route["outbound"]) == ("2", "edge"), new_route
        assert {row["route-target"] for row in old_rows + new_rows + [old_route, new_route]} == {
            f"127.0.0.1:{target}"
        }
        config.write_text(source.replace('selected "local"', 'selected "edge"'))
        replay = command(binary, "rule", "explain", config, "entry", "tcp", f"127.0.0.1:{target}")
        assert "rule=1 " in replay and "outbound=edge" in replay, replay
        for index, (peer, remote) in enumerate(old + new):
            data = str(index).encode()
            peer.sendall(data)
            assert exact(remote, len(data)) == data
            remote.sendall(data)
            assert exact(peer, len(data)) == data
        print(f"{mode} TCP and SOCKS5 UDP retained generation 1 local/direct and generation 2 edge/Trojan")


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    with (tempfile.TemporaryDirectory() as directory, socket.socket() as origin,
          socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp):
        root = Path(directory)
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(5)
        udp.bind(origin.getsockname())
        udp.settimeout(5)
        with trojan_server(binary, root) as edge:
            for ordered in (False, True):
                verify(binary, root, origin, udp, edge, ordered)
