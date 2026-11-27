#!/usr/bin/env python3
"""Exercise the raw CONNECT-IP device and its kernel routes in a private netns."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time

from udp_bind_port_network import certificate
from tailscale_endpoint_network import eventually, ip, line, process
from tun_inbound_e2e import tcp_echo_check
from dns_rule_support import DnsPeer, free_port, nexus_process
from named_http3_detour import private_file, trojan_listener
from masque_ip_outbound import ss_relay
from types import SimpleNamespace


NAME = "nx-masque-ip"


def capture(*args):
    return subprocess.run(args, text=True, capture_output=True, timeout=3, env={**os.environ, "LC_ALL": "C"})


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        return process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=3)
        raise


def wait_until(process, predicate):
    deadline = time.monotonic() + 5
    while process.poll() is None:
        if predicate():
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(.025)
    raise RuntimeError("CONNECT-IP TUN state did not converge")


def addresses():
    result = capture("ip", "-j", "address", "show", "dev", NAME)
    if result.returncode:
        return set()
    return {address["local"] for link in json.loads(result.stdout) for address in link["addr_info"]}


def routes():
    selected = set()
    for family in ("-4", "-6"):
        result = capture("ip", "-j", family, "route", "show", "dev", NAME)
        if result.returncode == 0:
            selected.update(route["dst"] for route in json.loads(result.stdout))
    return selected


def exchange(family, destination, payload):
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.connect((destination, 53))
        client.send(payload)
        if client.recv(2048) != payload:
            raise RuntimeError(f"CONNECT-IP TUN UDP payload mismatch for {destination}")


def rejects_invalid_hop(family, destination):
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(.2)
        client.connect((destination, 53))
        client.send(b"invalid-hop")
        try:
            client.recv(2048)
        except TimeoutError:
            return
    raise RuntimeError(f"CONNECT-IP accepted an encapsulated zero-hop packet from {destination}")


def verify_hop_expiry():
    with process(["unshare", "-n", "sleep", "20"]) as sender:
        netns = ("nsenter", "-t", str(sender.pid), "-n")
        eventually(lambda: os.stat(f"/proc/{sender.pid}/ns/net").st_ino != os.stat("/proc/self/ns/net").st_ino)
        ip("link", "add", "nx-ip-ingress", "type", "veth", "peer", "name", "nx-ip-sender")
        ip("link", "set", "nx-ip-sender", "netns", str(sender.pid))
        ip("link", "set", "nx-ip-ingress", "up")
        ip("link", "set", "nx-ip-sender", "up", prefix=netns)
        subprocess.run(["sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"], check=True)
        for family, local, remote, prefix, target, error in (
            ("-4", "192.0.2.1", "192.0.2.2", 24, "198.51.100.42", "time to live exceeded"),
            ("-6", "2001:db8:99::1", "2001:db8:99::2", 64, "2001:db8:42::42", "hop limit"),
        ):
            nodad = ("nodad",) if family == "-6" else ()
            ip(family, "address", "add", f"{local}/{prefix}", "dev", "nx-ip-ingress", *nodad)
            ip(family, "address", "add", f"{remote}/{prefix}", "dev", "nx-ip-sender", *nodad, prefix=netns)
            ip(family, "route", "add", "default", "via", local, prefix=netns)
            result = capture(*netns, "ping", family, "-n", "-t", "1", "-c", "1", "-W", "1", target)
            if error not in result.stdout.lower():
                raise RuntimeError(f"missing routed hop expiry for {target}: {result.stdout} {result.stderr}")


def expect_report(peer, expected):
    observed = []
    while select.select([peer.stdout], [], [], 3)[0]:
        line = peer.stdout.readline().decode().strip()
        observed.append(line)
        if line == expected:
            return
        if not line:
            break
    raise RuntimeError(f"missing ICMP report {expected!r}: {observed!r}")


def verify_tcp(binary, fixture, root, configuration, old_port):
    with process(["unshare", "-n", "sleep", "20"]) as remote:
        netns = ("nsenter", "-t", str(remote.pid), "-n")
        eventually(lambda: os.stat(f"/proc/{remote.pid}/ns/net").st_ino != os.stat("/proc/self/ns/net").st_ino)
        ip("link", "add", "nx-ip-outer", "type", "veth", "peer", "name", "nx-ip-peer")
        ip("link", "set", "nx-ip-peer", "netns", str(remote.pid))
        ip("address", "add", "192.0.2.1/24", "dev", "nx-ip-outer")
        ip("address", "add", "192.0.2.2/24", "dev", "nx-ip-peer", prefix=netns)
        ip("link", "set", "nx-ip-outer", "up")
        ip("link", "set", "lo", "up", prefix=netns)
        ip("link", "set", "nx-ip-peer", "up", prefix=netns)
        with process([*netns, fixture, root / "cert", root / "key", "tun", "192.0.2.2:0"]) as peer:
            port = int(line(peer).rsplit(b":", 1)[1])
            config = root / "tcp.kdl"
            config.write_text(configuration.replace(f'host="127.0.0.1" port={old_port}',
                                                     f'host="192.0.2.2" port={port}'))
            with process([binary, "run", "--config", config]) as nexus:
                wait_until(nexus, lambda: routes() == {"198.51.100.32/28", "2001:db8:42::/96"})
                tcp_echo_check(socket.AF_INET, "198.51.100.42", 18080, b"masque-v4-tcp" * 256)
                tcp_echo_check(socket.AF_INET6, "2001:db8:42::42", 18080, b"masque-v6-tcp" * 256)
            if capture("ip", "link", "show", "dev", NAME).returncode == 0:
                raise RuntimeError("CONNECT-IP TCP test left the TUN device installed")


def inner(binary, fixture, direct_binding=False):
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    with tempfile.TemporaryDirectory(prefix="nexus-masque-tun-") as tmp:
        root = Path(tmp)
        certificate(root)
        token = root / "bearer"
        token.write_text("approved\n")
        token.chmod(0o600)
        env = os.environ.copy()
        if direct_binding:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(("127.0.0.2", 0))
                source_port = reservation.getsockname()[1]
            env["NEXUS_TEST_CONNECT_IP_SOURCE"] = f"127.0.0.2:{source_port}"
        peer = subprocess.Popen([fixture, root / "cert", root / "key", "request"],
                                stdout=subprocess.PIPE, bufsize=0, env=env)
        try:
            if not select.select([peer.stdout], [], [], 5)[0]:
                raise RuntimeError("CONNECT-IP peer failed to start")
            port = int(peer.stdout.readline().rsplit(b":", 1)[1])
            config = root / "tun.kdl"
            config.write_text(f'''schema-version 1
role "client"
inbound "tun" type="tun" {{
    interface-name "{NAME}"
    connect-ip-outbound "edge"
    connect-ip-route "198.51.100.32/28"
    connect-ip-route "2001:db8:42::/96"
}}
outbound "direct" type="direct"
outbound "edge" type="masque" {{
    mode "connect-ip"
    server host="127.0.0.1" port={port}
    authority "localhost"
    authentication {{ bearer-file "{token}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
routing {{ final "direct"; }}
''')
            original = config.read_text()
            if direct_binding:
                config.write_text(original.replace('outbound "direct" type="direct"',
                    f'outbound "direct" type="direct" {{ inet4-bind-address "127.0.0.2"; udp-bind-port {source_port}; }}'
                ).replace('mode "connect-ip"', 'mode "connect-ip"\n    detour "direct"'))
            nexus = subprocess.Popen([binary, "run", "--config", config], text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                expected = {"198.51.100.32/28", "2001:db8:42::/96"}
                wait_until(nexus, lambda: routes() == expected and addresses() == {"10.10.0.2", "fd10::2"})
                selected = json.loads(capture("ip", "-j", "-4", "route", "get", "198.51.100.42").stdout)
                if selected[0].get("dev") != NAME or capture("ip", "-4", "route", "get", "198.51.100.96").returncode == 0:
                    raise RuntimeError("kernel installed a route outside the local allowlist")
                exchange(socket.AF_INET, "198.51.100.42", b"raw-ipv4")
                exchange(socket.AF_INET6, "2001:db8:42::42", b"raw-ipv6")
                rejects_invalid_hop(socket.AF_INET, "198.51.100.42")
                rejects_invalid_hop(socket.AF_INET6, "2001:db8:42::42")
                verify_hop_expiry()
                exchange(socket.AF_INET6, "2001:db8:42::42", b"x" * 1232)
                exchange(socket.AF_INET6, "2001:db8:42::42", b"mtu-report")
                expect_report(peer, "ptb 1280")
                time.sleep(.11)
                exchange(socket.AF_INET, "198.51.100.42", b"mtu-report")
                expect_report(peer, "frag-needed 1280")

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.sendto(b"withdraw-v6", ("198.51.100.42", 53))
                wait_until(nexus, lambda: addresses() == {"10.10.0.2"} and routes() == {"198.51.100.32/28"})
                exchange(socket.AF_INET, "198.51.100.42", b"ipv4-after-ipv6-withdrawal")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.sendto(b"clear-addresses", ("198.51.100.42", 53))
                wait_until(nexus, lambda: not addresses() and not routes())
                wait_until(nexus, lambda: addresses() == {"10.10.0.2", "fd10::2"} and routes() == expected)
                exchange(socket.AF_INET6, "2001:db8:42::42", b"ipv6-after-restore")

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.sendto(b"withdraw", ("198.51.100.42", 53))
                wait_until(nexus, lambda: not routes())
                if addresses() != {"10.10.0.2", "fd10::2"}:
                    raise RuntimeError("route withdrawal affected assigned addresses")
            finally:
                output, error = stop(nexus)
                if nexus.returncode:
                    raise RuntimeError(f"Nexus failed with {nexus.returncode}: {output} {error}")
            if capture("ip", "link", "show", "dev", NAME).returncode == 0:
                raise RuntimeError("CONNECT-IP TUN survived process stop")
        finally:
            stop(peer)
        verify_tcp(binary, fixture, root, original, port)
    print("CONNECT-IP TUN dual-stack TCP/UDP, ICMP MTU and hop expiry, address and route replacement and shutdown passed")


def layered(binary, fixture, through_ss, named_chain=False):
    ip("link", "set", "lo", "up")
    with tempfile.TemporaryDirectory(prefix="nexus-masque-tun-detour-") as tmp, ExitStack() as stack:
        root = Path(tmp)
        certificate(root)
        token = private_file(root, "bearer", "approved")
        if through_ss:
            relay_port, lower = stack.enter_context(ss_relay(root))
            source = "127.0.0.4"
        else:
            password = private_file(root, "password", "tun-detour-secret")
            relay_port = free_port()
            relay = trojan_listener(SimpleNamespace(root=root, secret=password), relay_port)
            if named_chain:
                relay.write_text(relay.read_text().replace('host="127.0.0.1"', 'host="::1"'))
            stack.enter_context(nexus_process(str(binary), relay))
            lower = f'''outbound "lower" type="trojan" {{
  server host="127.0.0.1" port={relay_port}
  authentication {{ password-file "{password}"; }}
  tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}'''
            source = "127.0.0.3"
        bootstrap = ""
        if named_chain:
            head_address = "::1"
            head_port = free_port()
            head = trojan_listener(SimpleNamespace(root=root, secret=password), head_port).rename(root / "head.kdl")
            head.write_text(head.read_text().replace('host="127.0.0.1"', f'host="{head_address}"'))
            stack.enter_context(nexus_process(str(binary), head))
            dns = stack.enter_context(DnsPeer())
            dns.delays.update({(name, 28): .12 for name in ("head.test", "middle.test")})
            bootstrap = f'''dns {{ server "bootstrap" type="udp" host="127.0.0.1" port={dns.port};
  final "bootstrap"; strategy "ipv6_only"; }}'''
            lower = lower.replace(f'host="127.0.0.1" port={relay_port}', f'host="middle.test" port={relay_port}')
            lower = lower.replace('  authentication', '  detour "head"\n  bootstrap-resolver "bootstrap"\n  connect-timeout-ms 50\n  authentication')
            lower += f'''
outbound "head" type="trojan" {{
  server host="head.test" port={head_port}
  bootstrap-resolver "bootstrap"\n  connect-timeout-ms 50
  tcp-fast-open #true
  authentication {{ password-file "{password}"; }}
  tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}'''
        env = dict(os.environ, NEXUS_TEST_CONNECT_IP_SOURCE=source)
        peer = stack.enter_context(subprocess.Popen([fixture, root / "cert", root / "key", "request"],
                                                    stdout=subprocess.PIPE, env=env))
        stack.callback(stop, peer)
        port = int(line(peer).rsplit(b":", 1)[1])
        config = root / "detour.kdl"
        body = f'''schema-version 1
role "client"
inbound "tun" type="tun" {{
  interface-name "{NAME}"
  connect-ip-outbound "edge"
  connect-ip-route "198.51.100.32/28"
  connect-ip-route "2001:db8:42::/96"
}}
outbound "direct" type="direct"
{lower}
outbound "edge" type="masque" {{
  mode "connect-ip"
  server host="127.0.0.1" port={port}
  detour "lower"
  authority "localhost"
  authentication {{ bearer-file "{token}"; }}
  tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
{bootstrap}
routing {{ final "direct"; }}
'''
        protected = ("127.0.0.1",) if named_chain else ("127.0.0.1", "192.0.2.3")
        for protected_host in protected:
            candidate = body.replace('connect-ip-route "198.51.100.32/28"', f'connect-ip-route "{protected_host}/32"')
            if protected_host != "127.0.0.1":
                candidate = candidate.replace(f'server host="127.0.0.1" port={relay_port}',
                                              f'server host="{protected_host}" port={relay_port}')
            config.write_text(candidate)
            bad = subprocess.run([binary, "run", "--config", config], capture_output=True, text=True, timeout=3)
            if not bad.returncode or "includes an outer server" not in bad.stderr or addresses():
                raise RuntimeError(f"TUN accepted a route covering {protected_host}: {bad.stderr}")
        if named_chain:
            config.write_text(body.replace('connect-ip-route "198.51.100.32/28"',
                                           f'connect-ip-route "{head_address}/128"'))
            bad = subprocess.run([binary, "run", "--config", config], capture_output=True, text=True, timeout=4)
            if not bad.returncode or "includes the connected physical detour peer" not in bad.stderr or addresses():
                raise RuntimeError(f"TUN did not reject its resolved physical peer: {bad.stderr}")
        config.write_text(body)
        with process([binary, "run", "--config", config]) as nexus:
            expected = {"198.51.100.32/28", "2001:db8:42::/96"}
            wait_until(nexus, lambda: routes() == expected and addresses() == {"10.10.0.2", "fd10::2"})
            exchange(socket.AF_INET, "198.51.100.42", b"detoured-v4")
            exchange(socket.AF_INET6, "2001:db8:42::42", b"detoured-v6")
            exchange(socket.AF_INET6, "2001:db8:42::42", b"x" * 1232)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(b"withdraw-v6", ("198.51.100.42", 53))
            wait_until(nexus, lambda: routes() == {"198.51.100.32/28"} and addresses() == {"10.10.0.2"})
            exchange(socket.AF_INET, "198.51.100.42", b"detoured-after-withdrawal")
        if capture("ip", "link", "show", "dev", NAME).returncode == 0:
            raise RuntimeError("detoured CONNECT-IP TUN survived stop")

        with socket.socket(socket.AF_INET6 if named_chain else socket.AF_INET) as blackhole:
            blackhole.bind(("::1" if named_chain else "127.0.0.1", 0))
            blackhole.listen(1)
            blackhole.settimeout(3)
            config.write_text(body.replace(f"port={relay_port}", f"port={blackhole.getsockname()[1]}"))
            with process(["stdbuf", "-oL", binary, "run", "--config", config]) as nexus:
                if b"TUN listening" not in line(nexus):
                    raise RuntimeError("TUN command did not start")
                with blackhole.accept()[0] as pending:
                    pending.settimeout(2)
                    if not pending.recv(4096) or addresses():
                        raise RuntimeError("TUN installed a device before the proxy handshake")
                    nexus.terminate()
                    if nexus.wait(timeout=2):
                        raise RuntimeError("TUN stop did not exit cleanly")
                    try:
                        while pending.recv(8192):
                            pass
                    except ConnectionResetError:
                        pass
    if named_chain and {(name, kind) for name, kind, _ in dns.seen} != {("head.test", 28), ("middle.test", 28)}:
        raise RuntimeError(f"wrong lower bootstrap queries: {dns.seen}")
    carrier = "named Trojan chain" if named_chain else "Shadowsocks UoT" if through_ss else "Trojan UDP"
    print(f"CONNECT-IP TUN through {carrier}, dual-stack routes, MTU, withdrawal, loop rejection and pending stop passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("peer", type=Path)
    parser.add_argument("--outer-namespaces", type=int, nargs=2)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--through-trojan", action="store_true")
    mode.add_argument("--through-ss", action="store_true")
    mode.add_argument("--named-chain", action="store_true")
    mode.add_argument("--direct-binding", action="store_true")
    args = parser.parse_args()
    binary, peer = args.binary.resolve(strict=True), args.peer.resolve(strict=True)
    current = tuple(os.stat("/proc/self/ns/" + name).st_ino for name in ("net", "user"))
    if args.outer_namespaces:
        if any(outer == inner_id for outer, inner_id in zip(args.outer_namespaces, current)):
            raise RuntimeError("fixture requires isolated user and network namespaces")
        if args.through_trojan or args.through_ss or args.named_chain:
            layered(binary, peer, args.through_ss, args.named_chain)
        else:
            inner(binary, peer, args.direct_binding)
    else:
        flags = [flag for flag, enabled in (("--through-trojan", args.through_trojan),
                 ("--through-ss", args.through_ss), ("--named-chain", args.named_chain), ("--direct-binding", args.direct_binding)) if enabled]
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, str(binary), str(peer),
                        "--outer-namespaces", *map(str, current), *flags], check=True, timeout=25)
