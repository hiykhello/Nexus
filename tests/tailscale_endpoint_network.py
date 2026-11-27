#!/usr/bin/env python3
"""Exercise a pair of production endpoints with a fixed Go Control and DERP peer."""
import argparse
import contextlib
import errno
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

from udp_bind_port_network import certificate
from wireguard_singbox import free_tcp_port, socks5_tcp_echo, socks5_udp_echo
from detour_network import exact


DEVICE = "nxmesh"


def ip(*args, prefix=()):
    return subprocess.check_output([*prefix, "ip", *args], text=True, timeout=3)


def eventually(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise RuntimeError("mesh state did not converge")


@contextlib.contextmanager
def process(args, **kwargs):
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    try:
        yield child
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            out, err = child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            out, err = child.communicate(timeout=3)
            raise RuntimeError(f"child failed to drain: {args[0]}, {out!r}, {err!r}")
        if child.returncode not in (0, -15):
            raise RuntimeError(f"child exit {child.returncode}: {out!r}, {err!r}")


def line(child):
    if not select.select([child.stdout], [], [], 10)[0]:
        raise RuntimeError("mesh startup deadline")
    value = child.stdout.readline()
    if not value:
        raise RuntimeError("mesh child exited before ready")
    return value


def configure(root, index, mode, peer):
    keys = root / f"state{index}"
    keys.mkdir(mode=0o700)
    identity = keys / "identity"
    machine_seed, node_seed = (3, 17) if index == 1 else (5, 51)
    identity.write_bytes(b"NXTAIL\x01\x00" + bytes(range(machine_seed, machine_seed + 32)) + bytes(range(node_seed, node_seed + 32)))
    identity.chmod(0o600)
    def relay_block(name, port, pin, region):
        return f'''{name} {{
            server-url "https://localhost:{port}"
            server-address "192.0.2.1"
            server-key "mkey:{pin}"
            ca-file "{root / 'cert'}"
            region-id {region}
        }}'''
    relay = ""
    if mode in ("relay", "paths"):
        relay = relay_block("derp", peer["port"], peer["derp"], 901)
    if mode == "dynamic":
        relay = "\n".join((
            relay_block("derp-candidate", peer["port"], peer["derp"], 901),
            relay_block("derp-candidate", peer["derp2_port"], peer["derp"], 902),
            relay_block("derp-candidate", peer["derp2_port"], peer["derp2"], 903),
        ))
    discovery = ""
    address = f"192.0.2.{index}"
    if mode == "paths":
        address = f"192.0.2.{10 + index}"
        discovery = f'discover-paths #true\n    stun-server host="192.0.2.1" port={peer["stun_port"]}'
    config = root / f"endpoint{index}.kdl"
    config.write_text(f'''schema-version 1
role "client"
endpoint "mesh{index}" type="tailscale" {{
    control-url "https://localhost:{peer['port']}"
    control-address "192.0.2.1"
    control-key "mkey:{peer['control']}"
    ca-file "{root / 'cert'}"
    auth-key-file "{root / 'auth'}"
    state-dir "{keys}"
    interface-name "{DEVICE}"
    listen host="{address}"
    listen-port 41234
    {relay}
    {discovery}
}}
''')
    return config


def routes(prefix=()):
    result = set()
    for family in ("-4", "-6"):
        links = json.loads(ip("-j", family, "route", "show", prefix=prefix))
        result.update(route["dst"] for route in links if route.get("dev") == DEVICE)
    return result


def echo():
    sockets = []
    workers = []
    connections = []
    stopping = threading.Event()

    def reply_tcp(client):
        with client:
            client.settimeout(.25)
            while not stopping.is_set():
                try:
                    data = client.recv(4096)
                    if not data:
                        return
                    client.sendall(data)
                except TimeoutError:
                    continue
                except (BrokenPipeError, ConnectionResetError):
                    return

    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        for port in (18080, 18081):
            sock = socket.socket(socket.AF_INET6, kind)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(("::",port))
            sock.settimeout(.1)
            if kind == socket.SOCK_STREAM:
                sock.listen(4)
            sockets.append(sock)

            def reply(sock=sock, kind=kind):
                while not stopping.is_set():
                    try:
                        if kind == socket.SOCK_DGRAM:
                            data, remote = sock.recvfrom(4096)
                            sock.sendto(data,remote)
                        else:
                            client, _ = sock.accept()
                            connection = threading.Thread(target=reply_tcp, args=(client,))
                            connections.append(connection)
                            connection.start()
                    except TimeoutError:
                        continue
            worker = threading.Thread(target=reply)
            worker.start()
            workers.append(worker)
    try:
        os.write(sys.stdout.fileno(),b"ready\n")
        sys.stdin.buffer.read(1)
    finally:
        stopping.set()
        for worker in workers:
            worker.join()
        for connection in connections:
            connection.join()
        for sock in sockets:
            sock.close()


def exchange(destination, kind, permitted=True, timeout=2):
    family = socket.AF_INET6 if ":" in destination else socket.AF_INET
    with socket.socket(family, kind) as sock:
        sock.settimeout(timeout if permitted else .5)
        port = 18080 if permitted else 18081
        body = b"mesh-echo"
        try:
            sock.connect((destination,port))
            sock.sendall(body)
            if sock.recv(2048) != body:
                raise RuntimeError("mesh round trip changed the payload")
        except TimeoutError:
            if not permitted:
                return False
            raise
        if not permitted:
            raise RuntimeError("mesh ACL allowed a blocked connection")
        return True


def roundtrip_after_handshake(destination, kind):
    deadline = time.monotonic() + 8
    while True:
        try:
            exchange(destination, kind, timeout=.5)
            return
        except TimeoutError:
            if time.monotonic() >= deadline:
                raise


def run_case(binary, fixture, root, child_prefix, mode):
    directory = root / mode
    directory.mkdir()
    certificate(directory)
    (directory / "auth").write_text("fixture-auth\n")
    (directory / "auth").chmod(0o600)
    trigger = directory / "withdraw"
    region = directory / "region"
    mapped, stats = directory / "mapped", directory / "stats"
    env = dict(os.environ, NEXUS_TS_MESH_MODE=mode, NEXUS_TS_MESH_WITHDRAW=str(trigger), NEXUS_TS_MESH_REGION=str(region),
               NEXUS_TS_MESH_STUN_OBSERVED=str(mapped), NEXUS_TS_MESH_DERP_STATS=str(stats))
    with process([fixture, "--cert", directory / "cert", "--key", directory / "key", "--listen", "192.0.2.1:0"], env=env) as control:
        peer = json.loads(line(control))
        first_cfg, second_cfg = (configure(directory, index, mode, peer) for index in (1,2))
        subprocess.run([binary, "endpoint", "check", "--config", first_cfg], check=True, timeout=5)
        first_cmd = [binary, "endpoint", "run", "--config", first_cfg]
        if mode == "direct":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
                occupied.bind(("192.0.2.1", 41234))
                failed = subprocess.run(first_cmd, capture_output=True, timeout=5)
                assert failed.returncode and b"cannot bind Tailscale UDP listener on port 41234" in failed.stderr, failed.stderr
            print("Tailscale listen-port 41234 conflicts cleanly")
        second_cmd = [*child_prefix, binary, "endpoint", "run", "--config", second_cfg]
        with process(first_cmd) as first, process(second_cmd) as second:
            for child in (first,second):
                if b"ready: device=nxmesh" not in line(child):
                    raise RuntimeError("missing production endpoint readiness")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
                try:
                    occupied.bind(("192.0.2.1", 41234))
                except OSError as error:
                    if error.errno != errno.EADDRINUSE:
                        raise
                else:
                    raise RuntimeError("Tailscale did not bind listen-port 41234")
            print("Tailscale UDP listen-port 41234 is bound")
            expected = {"100.64.21.2", "fd7a:115c:a1e0::2"}
            eventually(lambda: routes() == expected)
            with process([*child_prefix, sys.executable, __file__, "--echo"], stdin=subprocess.PIPE) as target:
                if line(target) != b"ready\n":
                    raise RuntimeError("mesh echo was not ready")
                for destination in ("100.64.21.2", "fd7a:115c:a1e0::2"):
                    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                        roundtrip_after_handshake(destination, kind)
                        exchange(destination,kind,False)

                port = free_tcp_port()
                proxy_config = directory / "proxy.kdl"
                proxy_config.write_text(f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct" {{ bind-interface "{DEVICE}"; }}
routing {{ final "direct"; }}
''')
                with process(["stdbuf", "-oL", binary, "run", "--config", proxy_config]) as proxy:
                    if b"SOCKS5 listening" not in line(proxy):
                        raise RuntimeError("mesh SOCKS5 proxy did not start")
                    for destination in ("100.64.21.2", "fd7a:115c:a1e0::2"):
                        socks5_tcp_echo(port, destination, 18080, b"mesh-proxy-tcp")
                        socks5_udp_echo(port, destination, 18080, b"mesh-proxy-udp")
                if mode == "paths":
                    eventually(mapped.exists)
                    eventually(stats.exists)

                    def relayed_packets():
                        if not stats.exists():
                            return 0
                        data = json.loads(stats.read_text())
                        return data["packets_received"]

                    def direct(kinds):
                        time.sleep(.15)
                        previous = relayed_packets()
                        for kind in kinds:
                            roundtrip_after_handshake("100.64.21.2", kind)
                        time.sleep(.15)
                        return relayed_packets() == previous

                    def active_echo(tcp, udp, payload):
                        tcp.sendall(payload)
                        udp.send(payload)
                        if exact(tcp, len(payload)) != payload or udp.recv(2048) != payload:
                            raise RuntimeError("active mesh traffic changed across a path switch")

                    eventually(lambda: direct((socket.SOCK_DGRAM, socket.SOCK_STREAM)))
                    destination = ("100.64.21.2", 18080)
                    with socket.create_connection(destination, timeout=5) as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.settimeout(5)
                        udp.connect(destination)
                        active_echo(tcp, udp, b"direct-before-switch")
                        ip("addr", "del", "192.0.2.12/32", "dev", "nxouter2", prefix=child_prefix)
                        try:
                            previous = relayed_packets()
                            time.sleep(3.5)
                            active_echo(tcp, udp, b"via-derp")
                            eventually(lambda: relayed_packets() > previous)
                        finally:
                            ip("addr", "add", "192.0.2.12/32", "dev", "nxouter2", prefix=child_prefix)
                        eventually(lambda: direct((socket.SOCK_DGRAM,)))
                        active_echo(tcp, udp, b"direct-after-switch")
                    mapped.with_suffix(".change").touch()
                    eventually(mapped.with_suffix(".changed").exists)
                    if mapped.with_suffix(".stale").exists():
                        raise RuntimeError("stale STUN transaction changed the advertised mapping")
                elif mode == "dynamic":
                    region.write_text("0")
                    eventually(lambda: not routes() and not routes(child_prefix))
                    region.write_text("902")
                    eventually(lambda: routes() == expected and len(routes(child_prefix)) == 2)
                    try:
                        exchange("100.64.21.2", socket.SOCK_DGRAM, timeout=1)
                    except TimeoutError:
                        pass
                    else:
                        raise RuntimeError("dynamic DERP accepted the wrong pin")
                    region.write_text("903")
                else:
                    trigger.touch()
                    eventually(lambda: not routes() and not routes(child_prefix))
                    trigger.unlink()
                eventually(lambda: routes() == expected and len(routes(child_prefix)) == 2)
                for destination in ("100.64.21.2", "fd7a:115c:a1e0::2"):
                    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                        roundtrip_after_handshake(destination, kind)
        for prefix in ((),child_prefix):
            links = json.loads(ip("-j", "link", "show", prefix=prefix))
            if routes(prefix) or any(link["ifname"] == DEVICE for link in links):
                raise RuntimeError("mesh routes or device remained after stop")
    print(f"Tailscale {mode}: dual-stack TCP/UDP and SOCKS routing, ingress ACL, Map withdrawal, reconnect and cleanup passed", flush=True)


def connect_socks(port, destination, target_port):
    socket_family = socket.AF_INET6 if ":" in destination else socket.AF_INET
    client = socket.create_connection(("127.0.0.1", port), timeout=12)
    try:
        client.sendall(b"\x05\x01\x00")
        if exact(client, 2) != b"\x05\x00":
            raise RuntimeError("Tailscale SOCKS greeting failed")
        kind = b"\x04" if socket_family == socket.AF_INET6 else b"\x01"
        client.sendall(b"\x05\x01\x00" + kind + socket.inet_pton(socket_family, destination) +
                       target_port.to_bytes(2, "big"))
        reply = exact(client, 4)
        exact(client, 18 if reply[3] == 4 else 6)
        return client, reply[1]
    except BaseException:
        client.close()
        raise


def run_outbound(binary, fixture, root, child_prefix, mode):
    directory = root / f"outbound-{mode}"
    directory.mkdir()
    certificate(directory)
    auth = directory / "auth"
    auth.write_text("fixture-auth\n")
    auth.chmod(0o600)
    trigger = directory / "withdraw"
    env = dict(os.environ, NEXUS_TS_MESH_MODE=mode, NEXUS_TS_MESH_WITHDRAW=str(trigger))
    with process([fixture, "--cert", directory / "cert", "--key", directory / "key", "--listen", "192.0.2.1:0"],
                 env=env) as control:
        peer = json.loads(line(control))
        outbound, endpoint = (configure(directory, index, mode, peer) for index in (1, 2))
        port = free_tcp_port()

        def tcp_roundtrip(host, payload):
            client, status = connect_socks(port, host, 18080)
            with client:
                if status:
                    raise RuntimeError(f"Tailscale userspace CONNECT failed for {host}: {status}")
                client.sendall(payload)
                if exact(client, len(payload)) != payload:
                    raise RuntimeError(f"Tailscale userspace TCP reply changed for {host}")

        config = directory / "proxy.kdl"
        allow = directory / "mesh-routes.kdl"
        allow.write_text('''schema-version 2
kind "predicate"
rule type="ip-cidr" value="100.64.21.2/32"
rule type="ip-cidr" value="fd7a:115c:a1e0::2/128"
''')
        config.write_text(f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "mesh" type="tailscale" {{ endpoint-file "{outbound}"; }}
routing {{
    rulesets {{ "mesh-hosts" format="kdl" path="mesh-routes.kdl"; }}
    rules {{ - kind="rule-set" value="mesh-hosts" outbound="mesh"; }}
    final "direct"
}}
''')
        with process([*child_prefix, binary, "endpoint", "run", "--config", endpoint]) as second, \
                process([*child_prefix, sys.executable, __file__, "--echo"], stdin=subprocess.PIPE) as target:
            if line(target) != b"ready\n" or b"ready: device=nxmesh" not in line(second):
                raise RuntimeError("Tailscale endpoint or echo did not start")
            with process(["stdbuf", "-oL", binary, "run", "--config", config]) as proxy:
                for _ in range(2):
                    if b"SOCKS5 listening" in line(proxy):
                        break
                else:
                    raise RuntimeError("Tailscale outbound proxy did not start")
                for host in ("100.64.21.2", "fd7a:115c:a1e0::2"):
                    tcp_roundtrip(host, b"userspace-tcp")
                    socks5_udp_echo(port, host, 18080, b"userspace-udp")
                blocked, result = connect_socks(port, "100.64.21.2", 18081)
                with blocked:
                    if result == 0:
                        raise RuntimeError("PacketFilter accepted a denied userspace outbound")
                active, result = connect_socks(port, "100.64.21.2", 18080)
                with active:
                    if result:
                        raise RuntimeError("could not open active Tailscale userspace flow")
                    active.settimeout(5)
                    trigger.touch()
                    eventually(lambda: not routes(child_prefix))
                    try:
                        data = active.recv(1)
                    except ConnectionResetError:
                        data = b""
                    if data:
                        raise RuntimeError("withdrawn userspace flow continued to deliver")
                    if routes() or DEVICE in ip("-j", "link", "show"):
                        raise RuntimeError("Tailscale userspace outbound created a system route or TUN")
                trigger.unlink()
                eventually(lambda: len(routes(child_prefix)) == 2)
                for host in ("100.64.21.2", "fd7a:115c:a1e0::2"):
                    tcp_roundtrip(host, b"userspace-restored-tcp")
                    socks5_udp_echo(port, host, 18080, b"userspace-restored-udp")
    print(f"Tailscale userspace {mode}: IP rule selection, dual-stack SOCKS5 traffic, withdrawal and recovery passed", flush=True)


def run(binary, fixture, cases):
    ip("link", "set", "lo", "up")
    with tempfile.TemporaryDirectory(prefix="nexus-tailnet-") as temp, \
            process(["unshare", "-n", "sleep", "120"]) as namespace:
        prefix = ("nsenter", "-t", str(namespace.pid), "-n")
        eventually(lambda: os.stat(f"/proc/{namespace.pid}/ns/net").st_ino != os.stat("/proc/self/ns/net").st_ino)
        ip("link", "add", "nxouter1", "type", "veth", "peer", "name", "nxouter2")
        ip("link", "set", "nxouter2", "netns", str(namespace.pid))
        for index, host_prefix in ((1,()),(2,prefix)):
            ip("link", "set", "lo", "up", prefix=host_prefix)
            ip("addr", "add", f"192.0.2.{index}/24", "dev", f"nxouter{index}", prefix=host_prefix)
            ip("link", "set", f"nxouter{index}", "up", prefix=host_prefix)
        for index, host_prefix in ((1,()),(2,prefix)):
            ip("addr", "add", f"192.0.2.{10 + index}/32", "dev", f"nxouter{index}", prefix=host_prefix)
        for case in cases:
            if case.startswith("outbound-"):
                run_outbound(binary,fixture,Path(temp),prefix,case.removeprefix("outbound-"))
            else:
                run_case(binary,fixture,Path(temp),prefix,case)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path)
    parser.add_argument("peer", nargs="?", type=Path)
    parser.add_argument("--outer", type=int, nargs=2)
    parser.add_argument("--echo", action="store_true")
    parser.add_argument("--case", action="append", choices=["direct", "relay", "dynamic", "paths", "outbound-direct", "outbound-relay"])
    args = parser.parse_args()
    if args.echo:
        echo()
    else:
        binary, peer = (arg.resolve(strict=True) for arg in (args.binary,args.peer))
        inode = tuple(os.stat("/proc/self/ns/" + name).st_ino for name in ("net","user"))
        if args.outer:
            if any(a == b for a, b in zip(args.outer,inode)):
                raise RuntimeError("mesh fixture requires private user and network namespaces")
            run(binary,peer,args.case or ["direct", "relay", "dynamic", "paths", "outbound-direct", "outbound-relay"])
        else:
            selected = [value for case in args.case or [] for value in ("--case", case)]
            subprocess.run(["unshare","-Urn",sys.executable,__file__,str(binary),str(peer),"--outer",*map(str,inode),*selected],
                           check=True, timeout=120)
