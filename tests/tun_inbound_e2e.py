#!/usr/bin/env python3
"""End-to-end TUN inbound test in an isolated Linux network namespace."""
import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from tailscale_endpoint_network import eventually, ip, line, process
from tun_dns_support import check_crash_recovery, check_kernel_bypass, check_strict_dns
from tun_udp_policy_support import check_udp_policy
from outbound_group_health_network import routed_tun as check_group_probe


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_tcp_echo(host, family=socket.AF_INET):
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    srv.listen(16)
    stop = threading.Event()

    def handle(c):
        with c:
            while not stop.is_set():
                try:
                    d = c.recv(65535)
                except OSError:
                    break
                if not d:
                    break
                c.sendall(d)

    def serve():
        srv.settimeout(0.1)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
            except TimeoutError:
                pass
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1], stop


def start_udp_echo(host, family=socket.AF_INET):
    srv = socket.socket(family, socket.SOCK_DGRAM)
    srv.bind((host, 0))
    srv.settimeout(0.1)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                d, p = srv.recvfrom(65535)
                srv.sendto(d, p)
            except TimeoutError:
                pass
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1], stop


def launch_nexus(nexus_bin, cfg_path, expected_line):
    proc = subprocess.Popen(
        ["stdbuf", "-oL", nexus_bin, "run", "--config", str(cfg_path)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    deadline = time.monotonic() + 8
    lines = []
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            continue
        lines.append(line.rstrip())
        if expected_line in line:
            return proc, line.strip()
    proc.kill()
    raise RuntimeError(f"nexus failed to start ({expected_line}):\n" + "\n".join(lines) + proc.stdout.read())


def tcp_echo_check(family, host, port, payload):
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((host, port))
        s.sendall(payload)
        got = bytearray()
        while len(got) < len(payload):
            c = s.recv(len(payload) - len(got))
            if not c:
                raise RuntimeError("unexpected EOF on TUN TCP")
            got.extend(c)
        if bytes(got) != payload:
            raise RuntimeError("TUN TCP echo mismatch")


def udp_echo_check(family, host, port, payload):
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        s.sendto(payload, (host, port))
        rx, _ = s.recvfrom(65535)
        if rx != payload:
            raise RuntimeError(f"TUN UDP echo mismatch: {rx!r}")



def run_strict_route(nexus_bin):
    ip("link", "set", "lo", "up")
    with tempfile.TemporaryDirectory(prefix="nexus-tun-strict-") as tmp, \
            process(["unshare", "-n", "sleep", "60"]) as namespace:
        prefix = ("nsenter", "-t", str(namespace.pid), "-n")
        eventually(lambda: os.stat(f"/proc/{namespace.pid}/ns/net").st_ino != os.stat("/proc/self/ns/net").st_ino)
        ip("link", "add", "nxphysical", "type", "veth", "peer", "name", "nxpeer")
        ip("link", "set", "nxpeer", "netns", str(namespace.pid))
        ip("link", "set", "nxphysical", "up")
        ip("link", "set", "lo", "up", prefix=prefix)
        ip("link", "set", "nxpeer", "up", prefix=prefix)
        ip("address", "add", "192.0.2.1/24", "dev", "nxphysical")
        ip("address", "add", "192.0.2.2/24", "dev", "nxpeer", prefix=prefix)
        ip("-6", "address", "add", "2001:db8:1::1/64", "dev", "nxphysical", "nodad")
        ip("-6", "address", "add", "2001:db8:1::2/64", "dev", "nxpeer", "nodad", prefix=prefix)
        config = Path(tmp) / "strict.kdl"
        config.write_text('''schema-version 1
role "client"
log { privacy "verbose"; }
inbound "tun" type="tun" {
    interface-name "nx-strict"
    inet4-address "198.51.100.1/32"
    inet6-address "2001:db8:2::1/128"
    auto-route #true
    strict-route #true
}
outbound "direct" type="direct"
routing { default-outbound "direct"; }
''')
        def rules():
            return [ip(family, "rule", "show") for family in ("-4", "-6")]

        saved_rules = rules()
        echo = Path(__file__).with_name("tailscale_endpoint_network.py")
        with process([*prefix, sys.executable, echo, "--echo"], stdin=subprocess.PIPE) as target:
            if line(target) != b"ready\n":
                raise RuntimeError("strict-route echo peer did not start")
            cli = [nexus_bin, "run", "--config", config]
            with process(["stdbuf", "-oL", *cli]) as nexus:
                if b"TUN listening on nx-strict" not in line(nexus):
                    raise RuntimeError("TUN strict-route did not start")
                for af, family, address, unreachable in (
                    (socket.AF_INET, "-4", "192.0.2.2", "198.51.100.85"),
                    (socket.AF_INET6, "-6", "2001:db8:1::2", "2001:db8:3::85"),
                ):
                    if "dev nx-strict" not in ip(family, "route", "get", address):
                        raise RuntimeError(f"strict-route bypassed capture for {address}")
                    if "dev nxphysical" not in ip(family, "route", "get", address, "mark", "0x6e780001"):
                        raise RuntimeError(f"strict-route bypass missed physical link for {address}")
                    failed = subprocess.run(["ip", family, "route", "get", unreachable, "mark", "0x6e780001"],
                                            capture_output=True, text=True, timeout=3)
                    if not failed.returncode or "unreachable" not in failed.stderr.lower():
                        raise RuntimeError("unroutable marked packet was not blocked")
                    tcp_echo_check(af, address, 18080, b"strict-tcp")
                    udp_echo_check(af, address, 18080, b"strict-udp")
            if rules() != saved_rules or subprocess.run(["ip", "link", "show", "nx-strict"],
                                                        capture_output=True).returncode == 0:
                raise RuntimeError("strict-route left policy rules or the TUN device")

            root = Path(tmp)
            check_strict_dns(nexus_bin, root, prefix, config.read_text())
            if rules() != saved_rules:
                raise RuntimeError("strict-route DNS left policy rules")
            check_udp_policy(nexus_bin, root, prefix, config.read_text())
            check_kernel_bypass(nexus_bin, root, config.read_text())
            assert rules()==saved_rules
            check_crash_recovery(nexus_bin, config)
            check_group_probe(nexus_bin, root, prefix)
            key = root / "ss.key"
            key.write_text(base64.b64encode(os.urandom(16)).decode() + "\n")
            key.chmod(0o600)
            server = root / "ss.json"
            server.write_text(json.dumps({
                "log": {"level": "error"},
                "inbounds": [{"type": "shadowsocks", "listen": "192.0.2.2", "listen_port": 18082,
                              "method": "2022-blake3-aes-128-gcm", "password": key.read_text().strip()}],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"final": "direct"},
            }))
            proxy = root / "proxy.kdl"
            proxy.write_text(config.read_text().replace(
                'routing { default-outbound "direct"; }',
                f'''outbound "ss" type="shadowsocks" {{
    server host="192.0.2.2" port=18082
    method "2022-blake3-aes-128-gcm"
    key-file "{key}"
    udp-over-tcp "v2"
}}
routing {{ default-outbound "ss"; }}'''))
            with process([*prefix, "/usr/bin/sing-box", "run", "-c", server]):
                eventually(lambda: "192.0.2.2:18082" in subprocess.check_output([*prefix, "ss", "-nlt"], text=True))
                with process(["stdbuf", "-oL", nexus_bin, "run", "--config", proxy]) as nexus:
                    if b"TUN listening on nx-strict" not in line(nexus):
                        raise RuntimeError("TUN strict-route proxy did not start")
                    tcp_echo_check(socket.AF_INET, "192.0.2.2", 18080, b"strict-proxy-tcp")
                    udp_echo_check(socket.AF_INET6, "2001:db8:1::2", 18080, b"strict-proxy-udp")

            ip("-4", "rule", "add", "priority", "10000", "lookup", "main")
            conflict_rules = rules()
            failed = subprocess.run(cli, capture_output=True, text=True, timeout=10)
            if not failed.returncode or "TUN strict-route installation failed" not in failed.stderr:
                raise RuntimeError(f"strict-route conflict was not rejected: {failed.stderr}")
            if rules() != conflict_rules or subprocess.run(["ip", "link", "show", "nx-strict"],
                                                            capture_output=True).returncode == 0:
                raise RuntimeError("strict-route conflict changed existing policy or left the TUN device")
            ip("-4", "rule", "del", "priority", "10000", "lookup", "main")
            changed, _ = launch_nexus(nexus_bin, config, "TUN listening on nx-strict")
            try:
                ip("-4", "route", "add", "203.0.113.0/24", "dev", "nxphysical")
                output, _ = changed.communicate(timeout=5)
                if not changed.returncode or "TUN strict-route policy changed" not in output:
                    raise RuntimeError(f"strict-route drift did not stop the host: {output}")
            finally:
                if changed.poll() is None:
                    changed.terminate()
                    changed.wait(timeout=5)
            if rules() != saved_rules or "203.0.113.0/24" not in ip("-4", "route", "show", "dev", "nxphysical"):
                raise RuntimeError("strict-route cleanup did not preserve the external change")
    print("Strict TUN dual-stack TCP/UDP, direct and SS UoT bypass, unreachable guard, conflict, drift and cleanup passed")


def run_netns_inner(nexus_bin, ordered=False, native_ss=False):
    for cmd in (
        ["ip", "link", "set", "lo", "up"],
        ["ip", "addr", "add", "10.88.0.2/32", "dev", "lo"],
        ["ip", "addr", "add", "10.88.0.3/32", "dev", "lo"],
        ["ip", "-6", "addr", "add", "fd88::2/128", "dev", "lo", "nodad", "noprefixroute"],
        ["ip", "-6", "addr", "add", "fd88::3/128", "dev", "lo", "nodad", "noprefixroute"],
        ["ip", "route", "add", "local", "10.88.0.2/32", "dev", "lo", "table", "100", "src", "10.88.0.3"],
        ["ip", "-6", "route", "add", "local", "fd88::2/128", "dev", "lo", "table", "100", "src", "fd88::3"],
        ["ip", "rule", "del", "priority", "0"],
        ["ip", "rule", "add", "priority", "1", "fwmark", "42", "lookup", "100"],
        ["ip", "rule", "add", "priority", "2", "to", "10.88.0.2/32", "table", "main"],
        ["ip", "rule", "add", "priority", "3", "lookup", "local"],
        ["ip", "-6", "rule", "del", "priority", "0"],
        ["ip", "-6", "rule", "add", "priority", "1", "fwmark", "42", "lookup", "100"],
        ["ip", "-6", "rule", "add", "priority", "2", "to", "fd88::2/128", "table", "main"],
        ["ip", "-6", "rule", "add", "priority", "3", "lookup", "local"],
    ):
        subprocess.run(cmd, check=True)

    tcp4, tcp4_port, tcp4_stop = start_tcp_echo("10.88.0.2", socket.AF_INET)
    udp4, udp4_port, udp4_stop = start_udp_echo("10.88.0.2", socket.AF_INET)
    tcp6, tcp6_port, tcp6_stop = start_tcp_echo("fd88::2", socket.AF_INET6)
    udp6, udp6_port, udp6_stop = start_udp_echo("fd88::2", socket.AF_INET6)

    with tempfile.TemporaryDirectory(prefix="nexus-tun-e2e-") as tmp:
        root = Path(tmp)
        key_f = root / "ss.key"
        key_f.write_text(base64.b64encode(os.urandom(16)).decode() + "\n")
        os.chmod(key_f, 0o600)

        # 1. TUN -> direct TCP/UDP (IPv4 + IPv6) + block CIDR rule
        block_rule = root / "block.kdl"
        block_rule.write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="10.88.0.99/32"\n')
        (root / "ingress.kdl").write_text(
            'schema-version 2\nkind "predicate"\nrule type="source-interface" value="nx-e2e0"\n')
        (root / "all.kdl").write_text('schema-version 2\nkind "predicate"\n'
            'rule type="ip-cidr" value="0.0.0.0/0"\nrule type="ip-cidr" value="::/0"\n')
        cfg_direct = root / "tun_direct.kdl"
        ingress = '''rules {
        - kind="rule-set" value="blk" outbound="block"
        - kind="rule-set" value="ingress" outbound="direct"
        - kind="rule-set" value="all" outbound="block"
    }'''
        extra_sets = 'rule-set "all" format="kdl" path="all.kdl"'
        if ordered:
            (root / "payload.kdl").write_text('schema-version 2\nkind "predicate"\n'
                'rule type="protocol" value="ssh"\nrule type="protocol" value="stun"\n')
            extra_sets = 'rule-set "payload" format="kdl" path="payload.kdl"'
            ingress = '''tcp-program sniff-timeout-ms=60 unknown="skip" udp=#true {
        rule action="reject" rule-set="blk"
        rule action="bypass"
        rule action="route-options" rule-set="ingress" connect-timeout-ms=2000
        rule action="sniff"
        rule action="reject" rule-set="payload"
        rule action="bypass" rule-set="ingress" outbound="direct" connect-timeout-ms=3000
        rule action="reject"
    }'''
        cfg_direct.write_text(f'''schema-version 1
role "client"
inbound "tun-in" type="tun" {{
    interface-name "nx-e2e0"
    inet4-address "10.88.0.1/24"
    inet6-address "fd88::1/64"
    mtu 1420
    auto-route #true
    socket-mark 42
}}
outbound "direct" type="direct"
outbound "block" type="block"
routing {{
    rule-set "blk" format="kdl" path="block.kdl"
    rule-set "ingress" format="kdl" path="ingress.kdl"
    {extra_sets}
    {ingress}
    default-outbound "direct"
}}
''')
        p_direct, _ = launch_nexus(nexus_bin, cfg_direct, "TUN listening on nx-e2e0")
        try:
            for family, target in (("-4", "10.88.0.2"), ("-6", "fd88::2")):
                unmarked = subprocess.check_output(["ip", family, "route", "get", target], text=True)
                marked = subprocess.check_output(["ip", family, "route", "get", target, "mark", "42"], text=True)
                if "dev nx-e2e0" not in unmarked or "dev lo" not in marked:
                    raise RuntimeError(f"unexpected TUN/bypass route for {target}: {unmarked} {marked}")
            for family, target in (("-4", "198.51.100.1"), ("-6", "2001:db8::1")):
                route = subprocess.check_output(["ip", family, "route", "get", target], text=True)
                if "dev nx-e2e0" not in route:
                    raise RuntimeError(f"automatic route missed {target}: {route}")
            tcp_echo_check(socket.AF_INET, "10.88.0.2", tcp4_port, b"tun-v4-tcp-" * 64)
            udp_echo_check(socket.AF_INET, "10.88.0.2", udp4_port, b"tun-v4-udp-ok")
            tcp_echo_check(socket.AF_INET6, "fd88::2", tcp6_port, b"tun-v6-tcp-" * 64)
            udp_echo_check(socket.AF_INET6, "fd88::2", udp6_port, b"tun-v6-udp-ok")
            if ordered:
                stun = bytes.fromhex("000100002112a4420102030405060708090a0b0c")
                for family, host, tcp_port, udp_port in (
                        (socket.AF_INET, "10.88.0.2", tcp4_port, udp4_port),
                        (socket.AF_INET6, "fd88::2", tcp6_port, udp6_port)):
                    with socket.socket(family, socket.SOCK_STREAM) as client:
                        client.settimeout(2)
                        client.connect((host, tcp_port))
                        client.sendall(b"SSH-2.")
                        client.sendall(b"0-dropbear\r\n")
                        try:
                            response = client.recv(64)
                        except ConnectionResetError:
                            response = b""
                        if response:
                            raise RuntimeError(f"ordered TUN forwarded rejected SSH data: {response!r}")
                    with socket.socket(family, socket.SOCK_DGRAM) as client:
                        client.settimeout(.3)
                        client.sendto(stun, (host, udp_port))
                        try:
                            raise RuntimeError(f"ordered TUN forwarded STUN: {client.recv(64)!r}")
                        except TimeoutError:
                            pass
                        client.sendto(stun[:-1], (host, udp_port))
                        client.settimeout(2)
                        if client.recv(64) != stun[:-1]:
                            raise RuntimeError("ordered TUN did not recover on ordinary UDP")
            # Blocked IPv4 target: user-space TCP engine accepts 3-way handshake and resets on route block
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bs:
                    bs.settimeout(1.5)
                    bs.connect(("10.88.0.99", 80))
                    bs.sendall(b"blocked")
                    rx = bs.recv(64)
                    if rx:
                        raise RuntimeError(f"blocked target unexpectedly replied: {rx!r}")
            except OSError:
                pass
        finally:
            p_direct.terminate()
            p_direct.wait(timeout=5)
        if subprocess.run(["ip", "link", "show", "nx-e2e0"], capture_output=True).returncode == 0:
            raise RuntimeError("nx-e2e0 remained after nexus exit")
        for family in ("-4", "-6"):
            routes = subprocess.check_output(["ip", family, "route", "show", "table", "main"], text=True)
            if "nx-e2e0" in routes:
                raise RuntimeError(f"{family} TUN routes survived shutdown: {routes}")
        print("E2E TUN -> direct IPv4/IPv6 TCP+UDP + block rule + clean teardown passed")

        # 2. TUN -> SS-2022 outbound -> SS-2022 Server (with socket-mark 42)
        ss_port = free_port()
        cfg_srv = root / "ss_srv.kdl"
        cfg_srv.write_text(f'''schema-version 1
role "server"
inbound "ss-in" type="shadowsocks" {{
    listen host="127.0.0.1" port={ss_port}
    method "2022-blake3-aes-128-gcm"
    key-file "{key_f}"
}}
outbound "direct" type="direct" {{
    routing-mark 42
}}
routing {{ default-outbound "direct"; }}
''')
        p_srv, srv_line = launch_nexus(nexus_bin, cfg_srv, "SS-2022 listening on ")
        actual_ss = int(srv_line.rsplit(":", 1)[1])

        cfg_tun_ss = root / "tun_ss.kdl"
        udp_mode = 'udp-mode "native"' if native_ss else 'udp-over-tcp "v2"'
        cfg_tun_ss.write_text(f'''schema-version 1
role "client"
inbound "tun-in" type="tun" {{
    interface-name "nx-e2e1"
    inet4-address "10.88.0.1/24"
    inet6-address "fd88::1/64"
    mtu 1420
    socket-mark 42
}}
outbound "direct" type="direct"
outbound "ss" type="shadowsocks" {{
    server host="127.0.0.1" port={actual_ss}
    method "2022-blake3-aes-128-gcm"
    key-file "{key_f}"
    {udp_mode}
}}
routing {{ default-outbound "ss"; }}
''')
        if ordered:
            text = cfg_tun_ss.read_text()
            cfg_tun_ss.write_text(text.replace('routing { default-outbound "ss"; }', '''routing {
    tcp-program sniff-timeout-ms=60 unknown="skip" udp=#true {
      rule action="route-options" connect-timeout-ms=2000
      rule action="bypass" outbound="ss"
    }
    default-outbound "ss"
}'''))
        p_tun_ss, _ = launch_nexus(nexus_bin, cfg_tun_ss, "TUN listening on nx-e2e1")
        try:
            tcp_echo_check(socket.AF_INET, "10.88.0.2", tcp4_port, b"tun-ss-v4-tcp-" * 32)
            udp_echo_check(socket.AF_INET, "10.88.0.2", udp4_port, b"tun-ss-v4-udp")
            tcp_echo_check(socket.AF_INET6, "fd88::2", tcp6_port, b"tun-ss-v6-tcp-" * 32)
            udp_echo_check(socket.AF_INET6, "fd88::2", udp6_port, b"tun-ss-v6-udp")
        finally:
            p_tun_ss.terminate()
            p_tun_ss.wait(timeout=5)
            p_srv.terminate()
            p_srv.wait(timeout=5)
        print(f"E2E TUN -> SS-2022 {'native UDP' if native_ss else 'UoT'} outbound IPv4/IPv6 TCP+UDP passed")

    for s in (tcp4_stop, udp4_stop, tcp6_stop, udp6_stop):
        s.set()
    for s in (tcp4, udp4, tcp6, udp6):
        s.close()


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--inner":
        run_netns_inner(sys.argv[2], native_ss="--native-ss" in sys.argv[3:])
    elif len(sys.argv) >= 3 and sys.argv[1] == "--ordered-inner":
        run_netns_inner(sys.argv[2], ordered=True, native_ss="--native-ss" in sys.argv[3:])
    elif len(sys.argv) >= 3 and sys.argv[1] == "--strict-inner":
        run_strict_route(sys.argv[2])
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("nexus_bin")
        parser.add_argument("--ordered", action="store_true")
        parser.add_argument("--native-ss", action="store_true")
        options = parser.parse_args()
        binary = str(Path(options.nexus_bin).resolve())
        extra = ["--native-ss"] if options.native_ss else []
        if options.ordered or options.native_ss:
            mode = "--ordered-inner" if options.ordered else "--inner"
            subprocess.run(["unshare", "-Urn", sys.executable, __file__, mode, binary, *extra], check=True, timeout=45)
            raise SystemExit(0)
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--inner", binary], check=True)
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--strict-inner", binary], check=True, timeout=45)
