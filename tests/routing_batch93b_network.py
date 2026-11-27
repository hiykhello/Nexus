#!/usr/bin/env python3
"""Exercise Linux ingress routing and strict-route ownership inside fresh netns."""
import contextlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from dns_rule_support import Echo, exact, free_port, nexus_process, stream_request
from tailscale_endpoint_network import eventually, ip, line, process
from tun_inbound_e2e import launch_nexus

FAMILIES = (
    (socket.AF_INET, "-4", "192.0.2.1", "192.0.2.2", 24, "10.19.0.2"),
    (socket.AF_INET6, "-6", "2001:db8:1::1", "2001:db8:1::2", 64, "fd19::2"),
)
MARK = 0x6E780001
OTHER_MAC = "02:aa:bb:cc:dd:ee"


@contextlib.contextmanager
def peer_link(local, peer, mac):
    with process(["unshare", "-n", "sleep", "120"]) as child:
        parent_ns = os.stat("/proc/self/ns/net").st_ino
        eventually(lambda: os.stat(f"/proc/{child.pid}/ns/net").st_ino != parent_ns)
        prefix = ("nsenter", "-t", str(child.pid), "-n")
        ip("link", "add", local, "type", "veth", "peer", "name", peer)
        ip("link", "set", peer, "netns", str(child.pid))
        ip("link", "set", peer, "address", mac, prefix=prefix)
        ip("link", "set", peer, "up", prefix=prefix)
        ip("link", "set", "lo", "up", prefix=prefix)
        ip("link", "set", local, "up")
        yield prefix


def traffic_class(sock, family, dscp):
    if family == socket.AF_INET:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, (dscp << 2) | 2)
    else:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, (dscp << 2) | 2)


def exchange(sock, endpoint, payload):
    sock.sendto(payload, endpoint)
    received, sender = sock.recvfrom(128)
    assert (received, sender[:2]) == (payload, endpoint), (received, sender)


def blocked(sock, endpoint):
    timeout = sock.gettimeout()
    sock.settimeout(.35)
    try:
        sock.sendto(b"blocked", endpoint)
        raise AssertionError(sock.recvfrom(128))
    except TimeoutError:
        pass
    finally:
        sock.settimeout(timeout)


def policy(root, source=None, ordered=False):
    predicates = ['dscp 0 46', 'gateway-mac "02:00:00:00:00:21"']
    if source:
        predicates.append(f'source-mac "{source}"')
    (root / "allow.kdl").write_text(
        'schema-version 2\nkind "predicate"\nall { ' + '; '.join(predicates) + '; }\n')
    (root / "deny.kdl").write_text(
        'schema-version 2\nkind "predicate"\nany { network "tcp"; network "udp"; }\n')
    declaration = '''    rulesets {
        allow path="allow.kdl" format="kdl"
'''
    if not ordered:
        declaration += '        deny path="deny.kdl" format="kdl"\n'
    declaration += '    }\n'
    actions = '''
    tcp-program sniff-timeout-ms=50 unknown="skip" udp=#true {
        rule action="route" rule-set="allow" outbound="direct"
        rule action="reject"
    }
''' if ordered else '''
    rules {
        - kind="rule-set" value="allow" outbound="direct"
        - kind="rule-set" value="deny" outbound="block"
    }
'''
    return f'''
outbound "direct" type="direct"
outbound "block" type="block"
routing {{{declaration}{actions}
    final "direct"
}}
'''


def snapshot():
    return [ip(family, *op.split()) for family in ("-4", "-6")
            for op in ("rule show", "route show table all")]


def check_tun(binary, root, ordered):
    with peer_link("nxphysical", "nxpeer", "02:00:00:00:00:21") as peer:
        for _, family, local, remote, width, private in FAMILIES:
            extra = ("nodad",) if family == "-6" else ()
            ip(family, "addr", "add", f"{local}/{width}", "dev", "nxphysical", *extra)
            ip(family, "addr", "add", f"{remote}/{width}", "dev", "nxpeer", *extra, prefix=peer)
            ip(family, "addr", "add", f"{private}/{32 if family == '-4' else 128}", "dev", "nxpeer", *extra, prefix=peer)
            ip(family, "neigh", "replace", remote, "lladdr", "02:00:00:00:00:21",
               "nud", "permanent", "dev", "nxphysical")
            ip(family, "route", "add", "default", "via", remote, "dev", "nxphysical")
        for address in ("10.19.0.2", "172.19.0.2", "192.168.4.2", "100.64.0.2", "169.254.0.2"):
            ip("-4", "route", "add", address, "dev", "nxphysical")
        ip("-6", "route", "add", "fd19::2", "dev", "nxphysical")

        config = root / "tun.kdl"
        config.write_text('''schema-version 1
role "client"
log { privacy "verbose"; }
inbound "tun" type="tun" {
    interface-name "nx-meta"
    inet4-address "198.51.100.1/32"
    inet6-address "2001:db8:2::1/128"
    auto-route #true
    strict-route #true
    include-routing-mark 0x20 mask=0xf0
    exclude-routing-mark 0x23
    route-exclude-private #true
    route-exclude "10.0.0.0/8"
}
''' + policy(root, ordered=ordered))
        before = snapshot()
        echo = Path(__file__).with_name("tailscale_endpoint_network.py")
        with process([*peer, sys.executable, echo, "--echo"], stdin=subprocess.PIPE) as target:
            assert line(target) == b"ready\n"
            nexus, _ = launch_nexus(binary, config, "TUN listening on nx-meta")
            try:
                for family, flag, _, remote, _, private in FAMILIES:
                    for mark, device in ((0, "nxphysical"), (0x2A, "nx-meta"),
                                         (0x23, "nxphysical"), (MARK, "nxphysical")):
                        assert f"dev {device}" in ip(flag, "route", "get", remote, "mark", str(mark))
                    for excluded in (private, "172.19.0.2", "192.168.4.2", "100.64.0.2", "169.254.0.2") if flag == "-4" else (private, "fe80::2"):
                        assert "dev nxphysical" in ip(flag, "route", "get", excluded, "mark", "0x2a")
                    endpoint = (remote, 18080)
                    with socket.socket(family, socket.SOCK_DGRAM) as udp:
                        udp.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x2A)
                        udp.settimeout(3)
                        traffic_class(udp, family, 46)
                        exchange(udp, endpoint, b"marked")
                        traffic_class(udp, family, 17)
                        blocked(udp, endpoint)
                        traffic_class(udp, family, 0)
                        exchange(udp, endpoint, b"default-dscp")
                    with socket.socket(family, socket.SOCK_STREAM) as tcp:
                        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x2A)
                        tcp.settimeout(3)
                        traffic_class(tcp, family, 46)
                        tcp.connect(endpoint)
                        tcp.sendall(b"syn-dscp")
                        assert exact(tcp, 8) == b"syn-dscp"
                    with socket.socket(family, socket.SOCK_STREAM) as tcp:
                        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x2A)
                        tcp.settimeout(3)
                        traffic_class(tcp, family, 17)
                        try:
                            tcp.connect(endpoint)
                            tcp.sendall(b"blocked")
                            assert tcp.recv(128) == b""
                        except (ConnectionResetError, BrokenPipeError):
                            pass
            finally:
                if nexus.poll() is None:
                    nexus.kill()
                assert nexus.wait(timeout=4) == -9
            eventually(lambda: snapshot() == before and
                       subprocess.run(["ip", "link", "show", "nx-meta"], capture_output=True).returncode)
            with process(["stdbuf", "-oL", binary, "run", "--config", config]) as restarted:
                assert b"TUN listening on nx-meta" in line(restarted)
            assert snapshot() == before
    print("routed TUN IPv4/IPv6 TCP and UDP DSCP, gateway MAC, mark precedence, private routes and SIGKILL cleanup")


def check_tun_forwarded(binary, root, ordered):
    with peer_link("nxphysical", "nxpeer", "02:00:00:00:00:21") as peer, \
            peer_link("nxsource", "nxclient", "02:00:00:00:00:11") as client:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1",
                        "net.ipv6.conf.all.forwarding=1"], check=True, capture_output=True)
        senders = []
        for family, flag, local, remote, width, _ in FAMILIES:
            incoming, sender = ("203.0.113.1", "203.0.113.2") if flag == "-4" else ("2001:db8:3::1", "2001:db8:3::2")
            for address, device, namespace in ((local, "nxphysical", ()), (remote, "nxpeer", peer),
                                                (incoming, "nxsource", ()), (sender, "nxclient", client)):
                ip(flag, "addr", "add", f"{address}/{width}", "dev", device,
                   *(("nodad",) if flag == "-6" else ()), prefix=namespace)
            ip(flag, "route", "add", "default", "via", remote, "dev", "nxphysical")
            ip(flag, "route", "add", "default", "via", incoming, prefix=client)
            ip(flag, "neigh", "replace", remote, "lladdr", "02:00:00:00:00:21",
               "nud", "permanent", "dev", "nxphysical")
            ip(flag, "neigh", "replace", sender, "lladdr", "02:00:00:00:00:11",
               "nud", "permanent", "dev", "nxsource")
            firewall = "iptables" if flag == "-4" else "ip6tables"
            subprocess.run([firewall, "-t", "mangle", "-A", "PREROUTING", "-i", "nxsource",
                            "-d", remote, "-j", "MARK", "--set-mark", "0x2a"], check=True)
            senders.append((family, remote, sender))
        config = root / "forwarded.kdl"
        config.write_text('''schema-version 1
role "client"
log { privacy "verbose"; }
inbound "tun" type="tun" {
    interface-name "nx-forwarded"
    inet4-address "198.51.100.1/32"
    inet6-address "2001:db8:2::1/128"
    auto-route #true
    strict-route #true
    include-routing-mark 0x2a
}
''' + policy(root, "02:00:00:00:00:11", ordered))
        code = """
import socket, sys
from routing_batch93b_network import traffic_class, exchange
family, remote, sender = int(sys.argv[1]), sys.argv[2], sys.argv[3]
with socket.socket(family, socket.SOCK_DGRAM) as udp:
    udp.bind((sender, 0))
    udp.settimeout(3)
    traffic_class(udp, family, 46)
    exchange(udp, (remote, 18080), b"forwarded")
"""
        echo = Path(__file__).with_name("tailscale_endpoint_network.py")
        with process([*peer, sys.executable, echo, "--echo"], stdin=subprocess.PIPE) as target:
            assert line(target) == b"ready\n"
            with process(["stdbuf", "-oL", binary, "run", "--config", config]) as nexus:
                assert b"TUN listening on nx-forwarded" in line(nexus)
                env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent))
                for family, remote, sender in senders:
                    subprocess.run([*client, sys.executable, "-c", code, str(family), remote, sender],
                                   env=env, check=True, timeout=6)
    print("forwarded TUN IPv4/IPv6 matched source MAC, gateway MAC and DSCP")


def check_tproxy(binary, root, ordered):
    with peer_link("nxorigin", "nxout", "02:00:00:00:00:21") as origin, \
            peer_link("nxingress", "nxclient", "02:00:00:00:00:11") as client:
        for family, flag, local, remote, width, _ in FAMILIES:
            incoming, sender = ("203.0.113.1", "203.0.113.2") if flag == "-4" else ("2001:db8:3::1", "2001:db8:3::2")
            gateway = "192.0.2.3" if flag == "-4" else "2001:db8:1::3"
            for address, device, namespace in ((local, "nxorigin", ()), (remote, "nxout", origin),
                                                (incoming, "nxingress", ()), (sender, "nxclient", client)):
                ip(flag, "addr", "add", f"{address}/{width}", "dev", device,
                   *(("nodad",) if flag == "-6" else ()), prefix=namespace)
            ip(flag, "route", "replace", "default", "via", gateway, "dev", "nxorigin")
            ip(flag, "route", "add", "default", "via", incoming, prefix=client)
            ip(flag, "neigh", "replace", gateway, "lladdr", "02:00:00:00:00:21",
               "nud", "permanent", "dev", "nxorigin")
            ip(flag, "neigh", "replace", sender, "lladdr", "02:00:00:00:00:11",
               "nud", "permanent", "dev", "nxingress")
            ip(flag, "rule", "add", "fwmark", "42", "lookup", "42")
            ip(flag, "route", "add", "local", "default", "dev", "lo", "table", "42")
            firewall = "iptables" if flag == "-4" else "ip6tables"
            subprocess.run([firewall, "-t", "mangle", "-A", "PREROUTING", "-i", "nxingress",
                            "-p", "udp", "-d", remote, "--dport", "18080", "-j", "TPROXY",
                            "--on-ip", incoming, "--on-port", "18081", "--tproxy-mark", "42"], check=True)
            config = root / "tproxy.kdl"
            config.write_text(f'''schema-version 1
role "client"
log {{ privacy "verbose"; }}
inbounds {{ tproxy "local" {{ udp #true; listen host="{incoming}" port=18081; }}; }}
''' + policy(root, "02:00:00:00:00:11", ordered))
            echo = Path(__file__).with_name("tailscale_endpoint_network.py")
            with process([*origin, sys.executable, echo, "--echo"], stdin=subprocess.PIPE) as target:
                assert line(target) == b"ready\n"
                with process([binary, "run", "--config", config]):
                    def listening():
                        try:
                            with socket.create_connection((incoming, 18081), timeout=.1):
                                return True
                        except OSError:
                            return False
                    eventually(listening)
                    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent))
                    code = """
import socket, sys
from routing_batch93b_network import traffic_class, exchange, blocked
family = int(sys.argv[1])
endpoint = (sys.argv[2], 18080)
with socket.socket(family, socket.SOCK_DGRAM) as sock:
    sock.settimeout(3)
    for value in (46, 17, 0):
        traffic_class(sock, family, value)
        if value == 17 or len(sys.argv) == 4:
            blocked(sock, endpoint)
        else:
            exchange(sock, endpoint, b'tproxy')
"""
                    command = [*client, sys.executable, "-c", code, str(family), remote]
                    subprocess.run(command, env=env, check=True, timeout=10)
                    ip(flag, "neigh", "replace", gateway, "lladdr", OTHER_MAC,
                       "nud", "permanent", "dev", "nxorigin")
                    # A route-only neighbor changes without altering either data path.
                    time.sleep(.25)
                    subprocess.run([*command, "blocked"], env=env, check=True, timeout=10)
                    ip(flag, "neigh", "replace", gateway, "lladdr", "02:00:00:00:00:21",
                       "nud", "permanent", "dev", "nxorigin")
                    time.sleep(.25)
                    subprocess.run(command, env=env, check=True, timeout=10)
    print("TPROXY IPv4/IPv6 UDP same-tuple DSCP changes, source MAC and refreshed gateway MAC")


def check_rules(binary, root):
    config = root / "query.kdl"
    rule_set = root / "metadata.kdl"
    headline = 'schema-version 2\nkind "predicate"\n'
    rule_set.write_text(headline + 'all { dscp 0 46 63; source-mac "02:00:00:00:00:11"; '
                        'not { gateway-mac "02:00:00:00:00:21"; }; }\n')
    base = [binary, "rule", "convert"]
    subprocess.run([*base, "kdl", "beve", rule_set, root / "metadata.beve"], check=True)
    subprocess.run([*base, "beve", "kdl", root / "metadata.beve", root / "converted.kdl"], check=True)
    for file, codec in ((rule_set, "kdl"), (root / "metadata.beve", "beve"), (root / "converted.kdl", "kdl")):
        config.write_text(f'''schema-version 1
role "client"
log {{ privacy "verbose"; }}
inbound "app" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }}
outbound "direct" type="direct"
routing {{
    rulesets {{ "metadata" path="{file}" format="{codec}"; }}
    tcp-program sniff-timeout-ms=50 unknown="skip" {{
        rule action="route" rule-set="metadata" outbound="direct"
        rule action="reject"
    }}
    final "direct"
}}
''')
        command = [binary, "rule", "explain", config, "app", "tcp", "192.0.2.2:443"]
        source = "source-mac=02:00:00:00:00:11"
        gateway = "gateway-mac=02:00:00:00:00:22"
        for value in (0, 46, 63):
            text = subprocess.check_output([*command, f"dscp={value}", source, gateway], text=True)
            assert "outbound=direct" in text, text
        text = subprocess.check_output([*command, "dscp=46", source], text=True)
        assert "unknown skipped" in text and "outbound=direct" not in text, text
        text = subprocess.check_output([*command, "dscp=1", source, gateway], text=True)
        assert "unknown skipped" not in text and "outbound=direct" not in text, text
    for invalid in ('dscp 64', 'dscp -1', 'dscp #true', 'source-mac "02:00:00:00:00:xyz"',
                    'gateway-mac "02:00:00:00:11"'):
        malformed = root / "malformed.kdl"
        malformed.write_text(headline + invalid + "\n")
        failed = subprocess.run([*base, "kdl", "beve", malformed, root / "malformed.beve"], capture_output=True)
        assert failed.returncode and not (root / "malformed.beve").exists(), (invalid, failed)
    port = free_port()
    config.write_text(f'''schema-version 1
role "client"
inbound "app" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{
    tcp-program sniff-timeout-ms=50 unknown="skip" {{
        rule action="reject" {{ dscp 0; }}
        rule action="reject" {{ not {{ dscp 46; }}; }}
        rule action="reject" {{ not {{ source-mac "02:00:00:00:00:11"; }}; }}
        rule action="reject" {{ not {{ gateway-mac "02:00:00:00:00:21"; }}; }}
        rule action="route" outbound="direct"
    }}
    final "direct"
}}
''')
    with Echo() as echo, nexus_process(binary, config):
        stream_request(port, echo.port, "127.0.0.1")
        stream_request(port, echo.port, "127.0.0.1", http=True)

    template = '''schema-version 1
role "client"
inbound "tun" type="tun" {
    inet4-address "198.51.100.1/32"
    auto-route #true
    strict-route #true
    OPTIONS
}
outbound "direct" type="direct"
routing { final "direct"; }
'''
    command = [binary, "rule", "explain", config, "tun", "tcp", "192.0.2.2:443"]
    config.write_text(template.replace("OPTIONS", 'include-routing-mark 0 mask=0xff'))
    subprocess.run(command, check=True, capture_output=True)
    for invalid in ('include-routing-mark 256 mask=255', 'exclude-routing-mark 0 mask=0',
                    'exclude-routing-mark 4294967296', 'include-routing-mark 1; include-routing-mark 2',
                    'route-exclude-private "true"', 'route-exclude-private #true'):
        text = template.replace("OPTIONS", invalid)
        if invalid.endswith("#true"):
            text = text.replace("strict-route #true", "strict-route #false")
        config.write_text(text)
        failed = subprocess.run(command, capture_output=True)
        assert failed.returncode, (invalid, failed)

    print("Metadata KDL/BEVE, three-valued NOT, ordinary SOCKS5/HTTP and TUN mark configuration passed")


if __name__ == "__main__":
    binary, mode = sys.argv[1:3]
    if mode == "rules":
        with tempfile.TemporaryDirectory(prefix="nexus-93b-rules-") as directory:
            check_rules(binary, Path(directory))
        raise SystemExit(0)
    if "--isolated" not in sys.argv:
        namespace = os.stat("/proc/self/ns/net").st_ino
        raise SystemExit(subprocess.call(["unshare", "-Urn", sys.executable, __file__,
                                         binary, mode, "--isolated", str(namespace)]))
    assert os.stat("/proc/self/ns/net").st_ino != int(sys.argv[-1])
    ip("link", "set", "lo", "up")
    with tempfile.TemporaryDirectory(prefix="nexus-93b-") as directory:
        if mode.startswith("tun-forwarded-"):
            check = check_tun_forwarded
        else:
            check = check_tun if mode.startswith("tun-") else check_tproxy
        check(binary, Path(directory), mode.endswith("-ordered"))
