#!/usr/bin/env python3
"""Verify configured proxy UDP fragmentation on actual IPv4/IPv6 wire packets."""

import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

import udp_fragment_network as net
from anytls_test_peer import address
from dns_rule_support import nexus_process, proxy_client, udp_client
from socket_binding_network import client_config, client_node, server_config, REVISION
from tcp_keepalive_network import reserve


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--isolated", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--parent-user", help=argparse.SUPPRESS)
    parser.add_argument("--parent-net", help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary, evidence = args.binary.resolve(strict=True), args.evidence.resolve()
    if not args.isolated:
        subprocess.run(["unshare", "-Urn", sys.executable, str(Path(__file__).resolve()), str(binary),
            "--evidence", str(evidence), "--isolated", "--parent-user", net.namespace("user"),
            "--parent-net", net.namespace("net")], check=True)
        return
    assert net.namespace("net") != args.parent_net and net.namespace("user") != args.parent_user
    if f"Revision: {REVISION}" not in net.command(["sing-box", "version"]).stdout:
        raise RuntimeError("unexpected fixed peer revision")
    evidence.parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="nexus-udp-fragment-cli-"))
    net.command(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", root / "key", "-out", root / "cert", "-days", "1", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost"])
    for name, value in [("uuid", "00010203-0405-0607-0809-0a0b0c0d0e0f"), ("password", "binding-secret"),
                        ("psk", base64.b64encode(bytes(range(16))).decode())]:
        (root / name).write_text(value + "\n")
        (root / name).chmod(0o600)
    (root / "key").chmod(0o600)
    net.command(["ip", "link", "set", "lo", "up"])
    helper = Path(net.__file__).resolve()
    peer = subprocess.Popen(["unshare", "-n", sys.executable, str(helper), "--peer", "--parent-user",
        net.namespace("user"), "--parent-net", net.namespace("net")], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    frames, results = [], []
    stop, packet, thread, complete = threading.Event(), None, None, False
    try:
        assert net.ready(peer)["pid"] == peer.pid
        net.command(["ip", "link", "add", "nxfa", "type", "veth", "peer", "name", "nxfb"])
        net.command(["ip", "link", "set", "nxfb", "netns", peer.pid])
        for prefix, index in [([], 1), (["nsenter", "-t", str(peer.pid), "-n"], 2)]:
            device = "nxfa" if index == 1 else "nxfb"
            net.command([*prefix, "ip", "link", "set", "lo", "up"])
            net.command([*prefix, "ip", "link", "set", device, "mtu", "1280"])
            net.command([*prefix, "ip", "addr", "add", f"10.77.0.{index}/24", "dev", device])
            net.command([*prefix, "ip", "-6", "addr", "add", f"fd77::{index}/64", "dev", device, "nodad"])
            net.command([*prefix, "ip", "link", "set", device, "up"])
        peer.stdin.write("go\n"); peer.stdin.flush()
        ports = net.ready(peer)["ports"]
        packet = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        packet.bind(("nxfa", 0))
        thread = threading.Thread(target=net.capture, args=(packet, stop, frames))
        thread.start()

        def snapshot():
            peer.stdin.write("snapshot\n"); peer.stdin.flush()
            return net.ready(peer)["seen"]

        def datagrams(front, family, fragment):
            host = "10.77.0.2" if family == 4 else "fd77::2"
            header = bytes(3) + address(host, ports[family == 6])
            before, start = len(snapshot()), len(frames)
            with udp_client(front) as (client, relay):
                for size in [0, 1200, 2048]:
                    payload = bytes((i * 71) % 256 for i in range(size))
                    client.sendto(header + payload, relay)
                    client.settimeout(3 if fragment or size != 2048 else .2)
                    try:
                        response = client.recvfrom(65535)[0]
                    except TimeoutError:
                        if fragment or size != 2048:
                            raise
                    else:
                        if response != header + payload or (not fragment and size == 2048):
                            raise RuntimeError("UDP fragment policy/address/boundary mismatch")
            # A rejected large datagram may retire the enclosing stream. A
            # fresh authorized association must still transfer normally.
            with udp_client(front) as (client, relay):
                payload = bytes((i * 71) % 256 for i in range(256))
                client.sendto(header + payload, relay)
                if client.recvfrom(65535)[0] != header + payload:
                    raise RuntimeError("new association did not recover")
            received = snapshot()[before:]
            assert sorted(item["size"] for item in received) == ([0, 256, 1200, 2048] if fragment else [0, 256, 1200])
            time.sleep(.03)
            wire = frames[start:]
            fragments = [item for item in wire if item["family"] == family and (item["more"] or item["offset"])]
            if fragment:
                assert len(fragments) >= 2 and any(item["offset"] == 0 and item["more"] for item in fragments)
                assert any(item["offset"] > 0 and not item["more"] for item in fragments)
                assert all(item["size"] <= 1280 for item in fragments)
            else:
                assert not fragments
            return {"family": family, "received": received, "wire": wire}

        for workers in (1, 2):
            for kind in ("socks5", "ss-native", "ss", "vless", "vision", "upgrade", "trojan", "anytls"):
                for fragment in (False, True):
                    port, front = reserve(), reserve()
                    label = f"{kind}-w{workers}-fragment{int(fragment)}"
                    fields = f'bind-interface "nxfa"; inet4-bind-address "10.77.0.1"; inet6-bind-address "fd77::1"; udp-fragment #{str(fragment).lower()};'
                    config = root / (label + ".kdl")
                    config.write_text(server_config(root, port, kind, workers, fields))
                    with nexus_process(binary, config), contextlib.ExitStack() as stack:
                        if kind == "socks5":
                            entry = port
                        elif kind == "ss-native":
                            entry = stack.enter_context(proxy_client(root, {"type": "shadowsocks", "server": "127.0.0.1",
                                "server_port": port, "method": "2022-blake3-aes-128-gcm",
                                "password": base64.b64encode(bytes(range(16))).decode()}))
                        else:
                            path = root / "client.kdl"
                            path.write_text(client_config(root, front, client_node(root, kind, port), workers))
                            stack.enter_context(nexus_process(binary, path))
                            entry = front
                        observed = [datagrams(entry, family, fragment) for family in (4, 6)]
                    results.append({"case": label, "exit": 0, "families": observed})
                    print(label, "actual v4/v6 fragmentation, empty packets and new association recovery passed", flush=True)
        complete = True
    finally:
        stop.set()
        if thread:
            thread.join(1)
        if packet:
            packet.close()
        if peer.poll() is None:
            try:
                peer.stdin.write("stop\n"); peer.stdin.flush(); peer.communicate(timeout=2)
            except BaseException:
                peer.kill(); peer.communicate()
        evidence.write_text(json.dumps({"complete": complete, "expected_cases": 32, "cases": results,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "artifacts": str(root)}, indent=2) + "\n")


if __name__ == "__main__":
    main()
