#!/usr/bin/env python3
"""Verify direct socket interface selection against independent veth peers."""
from contextlib import ExitStack, contextmanager
import ipaddress
from pathlib import Path
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time

from detour_network import exact, reserve, running
from network_state_network import ip, status
from tailscale_endpoint_network import eventually


TARGETS = ("203.0.113.77", "2001:db8:ef::77")
LINKS = (
    ("primary", "192.0.2.2", "192.0.2.1", "2001:db8:1::2", "2001:db8:1::1", "40"),
    ("backup", "198.51.100.2", "198.51.100.1", "2001:db8:2::2", "2001:db8:2::1", "10"),
)

PEER = r"""
import selectors, socket, sys, threading
name, port, *targets = sys.argv[1:]
def tcp(peer):
    with peer:
        while data := peer.recv(256):
            if data.startswith(b"HEAD "):
                code = b"204 No Content" if name == "primary" else b"503 Unavailable"
                peer.sendall(b"HTTP/1.1 " + code + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            peer.sendall(name.encode() + b":" + data)
with selectors.DefaultSelector() as sockets:
    for target in targets:
        family = socket.AF_INET6 if ":" in target else socket.AF_INET
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            endpoint = socket.socket(family, kind)
            endpoint.bind((target, int(port)))
            if kind == socket.SOCK_STREAM:
                endpoint.listen()
            sockets.register(endpoint, selectors.EVENT_READ, kind)
    print("ready", flush=True)
    while True:
        for key, _ in sockets.select():
            if key.data == socket.SOCK_STREAM:
                peer, _ = key.fileobj.accept()
                threading.Thread(target=tcp, args=(peer,), daemon=True).start()
            else:
                data, remote = key.fileobj.recvfrom(256)
                key.fileobj.sendto(name.encode() + b":" + data, remote)
"""


@contextmanager
def process(args):
    with subprocess.Popen(args, stdout=subprocess.PIPE, text=True) as child:
        try:
            assert select.select([child.stdout], [], [], 4)[0] and child.stdout.readline().strip() == "ready", args
            yield child.pid
        finally:
            child.terminate()
            child.wait(timeout=5)


def prefix(address):
    return f'{address}/{32 if ":" not in address else 128}'


def default_route(link, add):
    name, _, gateway4, _, gateway6, metric = link
    for gateway in (gateway4, gateway6):
        ip("route", "add" if add else "del", "default", "via", gateway, "dev", name, "metric", metric)


def peers(stack, port):
    namespaces = {}
    ip("link", "set", "lo", "up")
    # Loose validation allows both valid reverse paths even when their metrics differ.
    Path("/proc/sys/net/ipv4/conf/all/rp_filter").write_text("2\n")
    for link in LINKS:
        name, source4, gateway4, source6, gateway6, metric = link
        namespace = stack.enter_context(process(["unshare", "-n", "sh", "-c", "echo ready; exec sleep 60"]))
        namespaces[name] = namespace
        ns = ["nsenter", "-t", str(namespace), "-n", "--"]

        def remote(*arguments):
            subprocess.run([*ns, "ip", *arguments], check=True, capture_output=True)

        ip("link", "add", name, "type", "veth", "peer", "name", "egress")
        ip("link", "set", "egress", "netns", str(namespace))
        ip("link", "set", name, "up")
        remote("link", "set", "lo", "up")
        remote("link", "set", "egress", "up")
        ip("addr", "add", f"{source4}/24", "dev", name)
        ip("addr", "add", f"{source6}/64", "dev", name, "nodad")
        remote("addr", "add", f"{gateway4}/24", "dev", "egress")
        remote("addr", "add", f"{gateway6}/64", "dev", "egress", "nodad")
        for target, gateway in zip(TARGETS, (gateway4, gateway6), strict=True):
            remote("addr", "add", prefix(target), "dev", "lo")
            # Specific routes let old sockets continue forwarding after a
            # default withdrawal and make accidental unbound fallback observable.
            ip("route", "add", prefix(target), "via", gateway, "dev", name, "metric", metric)
        default_route(link, True)
        stack.enter_context(process([*ns, sys.executable, "-u", "-c", PEER, name, str(port), *TARGETS]))
    return namespaces


@contextmanager
def stall_primary_connects(namespace, port, udp=False):
    command = ["nsenter", "-t", str(namespace), "-n", "--", "nft"]
    match = f"udp dport {port}" if udp else f"tcp dport {port} tcp flags & (syn | ack) == syn"
    rules = f"""table inet nexus_test {{
    chain input {{
        type filter hook input priority 0; policy accept;
        {match} drop
    }}
}}
"""
    subprocess.run([*command, "-f", "-"], input=rules, text=True, check=True)
    try:
        yield
    finally:
        subprocess.run([*command, "delete", "table", "inet", "nexus_test"], check=True)


def address(target, port):
    ip_address = ipaddress.ip_address(target)
    return (b"\x01" if ip_address.version == 4 else b"\x04") + ip_address.packed + struct.pack("!H", port)


def socks(front, command, target, port):
    client = socket.create_connection(("127.0.0.1", front), timeout=3)
    try:
        client.sendall(b"\x05\x01\x00")
        assert exact(client, 2) == b"\x05\x00"
        client.sendall(b"\x05" + bytes([command, 0]) + address(target, port))
        reply = exact(client, 4)
        endpoint = exact(client, 6 if reply[3] == 1 else 18)
        return client, reply[1], endpoint
    except BaseException:
        client.close()
        raise


def tcp(front, target, port, label, stack):
    client, code, _ = socks(front, 1, target, port)
    stack.enter_context(client)
    assert code == (0 if label else 3), (target, code)
    if label:
        verify_tcp(client, label)
    return client


def verify_tcp(client, label):
    client.sendall(b"tcp")
    reply = label.encode() + b":tcp"
    assert exact(client, len(reply)) == reply, label


def udp(front, stack):
    control, code, endpoint = socks(front, 3, "0.0.0.0", 0)
    stack.enter_context(control)
    assert code == 0
    assoc = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    assoc.settimeout(.4)
    return assoc, (socket.inet_ntoa(endpoint[:4]), struct.unpack("!H", endpoint[4:])[0])


def verify_udp(association, target, port, label):
    sock, relay = association
    header = b"\0\0\0" + address(target, port)
    sock.sendto(header + b"udp", relay)
    try:
        reply, _ = sock.recvfrom(256)
    except TimeoutError:
        assert label is None, target
        return
    assert label and reply == header + label.encode() + b":udp", (target, label, reply)


def check(binary):
    with ExitStack() as stack, tempfile.TemporaryDirectory(prefix="nexus-network-select-") as directory:
        root = Path(directory)
        config = root / "proxy.kdl"
        control = root / "control.sock"
        front, origin = reserve(), reserve()
        namespaces = peers(stack, origin)
        config.write_text(f'''schema-version 1
role "client"
workers 2
control socket="{control}"
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}; }}
outbounds {{
  direct "direct" {{
    network strategy="prefer" type="ethernet" fallback="wifi" fallback-delay-ms=125 {{
      interface "primary" type="ethernet"
      interface "backup" type="wifi"
    }}
  }}
  fallback "sample" {{
    member "direct"
    probe-url "http://{TARGETS[0]}:{origin}/health"
    probe-interval-ms 60000
    probe-timeout-ms 900
  }}
}}
routing {{ default-outbound "sample"; }}
''')
        with running([binary, "run", "--config", str(config)], front, root / "proxy.log"):
            def check_sample(state):
                def check():
                    health = subprocess.run([binary, "control", control, "group-health", "sample"],
                                            capture_output=True, text=True, timeout=3)
                    return health.returncode==0 and f"member=direct state={state}" in health.stdout
                eventually(check)

            generation = status(binary, control, 0, ("2", "2"))
            check_sample("up")
            primary_tcp = [tcp(front, target, origin, "primary", stack) for target in TARGETS]
            primary_udp = udp(front, stack)
            for target in TARGETS:
                verify_udp(primary_udp, target, origin, "primary")

            with stall_primary_connects(namespaces["primary"], origin):
                for target in TARGETS:
                    started = time.monotonic()
                    tcp(front, target, origin, "backup", stack)
                    assert .10 <= time.monotonic() - started < 2, target
            for client in primary_tcp:
                verify_tcp(client, "primary")

            udp_retry = udp(front, stack)
            target6 = TARGETS[1]
            ip("-6", "rule", "add", "pref", "212", "oif", "primary", "to", prefix(target6), "unreachable")
            try:
                verify_udp(udp_retry, target6, origin, "backup")
            finally:
                ip("-6", "rule", "del", "pref", "212")

            default_route(LINKS[0], False)
            generation = status(binary, control, generation, ("1", "1"))
            check_sample("down")
            backup_udp = udp(front, stack)
            for target in TARGETS:
                tcp(front, target, origin, "backup", stack)
                verify_udp(backup_udp, target, origin, "backup")
                verify_udp(primary_udp, target, origin, "primary")
            for client in primary_tcp:
                verify_tcp(client, "primary")

            default_route(LINKS[1], False)
            generation = status(binary, control, generation, ("0", "0"))
            pending = udp(front, stack)
            for target in TARGETS:
                tcp(front, target, origin, None, stack)
                verify_udp(pending, target, origin, None)

            default_route(LINKS[0], True)
            status(binary, control, generation, ("1", "1"))
            check_sample("up")
            for target in TARGETS:
                tcp(front, target, origin, "primary", stack)
                verify_udp(pending, target, origin, "primary")
    print("Dual-stack TCP retried stalled SYNs, IPv6 UDP retried an unreachable route, and established paths were retained")


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    namespace = os.stat("/proc/self/ns/net").st_ino
    if len(sys.argv) == 2:
        subprocess.run(["unshare", "-Urn", "--", sys.executable, __file__, binary, str(namespace)], check=True)
    else:
        assert int(sys.argv[2]) != namespace
        check(binary)
