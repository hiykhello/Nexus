"""DNS peers and assertions for the isolated strict-route TUN fixture."""
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path

from dns_rule_support import dns_request, exact, free_port, wire_name
from tailscale_endpoint_network import eventually, ip, line, process


def check_strict_dns(nexus_bin, root, prefix, config):
    peer = """import sys
from dns_rule_support import DnsPeer
with DnsPeer(host="192.0.2.2") as ipv4, DnsPeer(ipv6=True, host="2001:db8:1::2") as ipv6:
    print(ipv4.port, ipv6.port)
    sys.stdin.buffer.read(1)
"""
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent))
    with process([*prefix, sys.executable, "-u", "-c", peer], stdin=subprocess.PIPE, env=env) as upstream:
        udp_port, tcp_port = map(int, line(upstream).split())
        listen = free_port()
        (root / "strict-dns-targets.kdl").write_text(
            'schema-version 2\nkind "predicate"\n'
            'rule type="ip-cidr" value="198.51.100.85/32"\n'
            'rule type="ip-cidr" value="2001:db8:3::85/128"\n')
        dns = root / "strict-dns.kdl"
        dns.write_text(config[:config.index("routing {")] + f'''dns {{
    listen host="127.0.0.1" port={listen}
    server "v4" type="udp" host="192.0.2.2" port={udp_port}
    server "v6" type="tcp" host="2001:db8:1::2" port={tcp_port}
    rule query-type="AAAA" server="v6"
    final "v4"
}}
routing {{
    rulesets {{ "dns-targets" path="strict-dns-targets.kdl" format="kdl"; }}
    tcp-program sniff-timeout-ms=60 unknown="skip" udp=#true {{
        rule action="hijack-dns" rule-set="dns-targets"
        rule action="reject"
    }}
    final "direct"
}}
''')
        with process(["stdbuf", "-oL", nexus_bin, "run", "--config", dns]) as nexus:
            if b"TUN listening on nx-strict" not in line(nexus):
                raise RuntimeError("strict-route DNS did not start")
            assert dns_request(listen, "bypass.test") == (0, "127.0.0.1")
            assert dns_request(listen, "bypass.test", socket.SOCK_STREAM, kind=28) == (0, "::1")
            for family, target, qtype, answer in (
                (socket.AF_INET, "198.51.100.85", 1, "127.0.0.1"),
                (socket.AF_INET6, "2001:db8:3::85", 28, "::1"),
            ):
                question = wire_name("intercept.test") + struct.pack("!HH", qtype, 1)
                request = struct.pack("!6H", 0x6123, 0x0100, 1, 0, 0, 0) + question
                with socket.socket(family, socket.SOCK_DGRAM) as client:
                    client.settimeout(3)
                    client.sendto(request, (target, 53))
                    response, source = client.recvfrom(4096)
                assert source[:2] == (target, 53), source
                address = socket.inet_pton(family, answer)
                assert response[:2] == request[:2] and response.endswith(address), response.hex()
    print("TUN strict-route DNS interception and physical bypass passed for both families")


def check_kernel_bypass(nexus_bin, root, baseline):
    config = root / "strict-excluded.kdl"
    excluded = '''strict-route #true
    route-exclude "192.0.2.0/24"
    route-exclude "2001:db8:1::/64"
    route-exclude "198.51.100.85/32"
'''
    text = baseline.replace("strict-route #true", excluded)
    text = text.replace('routing { final "direct"; }', '''routing {
    tcp-program sniff-timeout-ms=60 unknown="skip" udp=#true { rule action="reject"; }
    final "direct"
}
''')
    config.write_text(text)
    with process(["stdbuf", "-oL", nexus_bin, "run", "--config", config]) as nexus:
        assert b"TUN listening on nx-strict" in line(nexus)
        for family, switch, target, captured in (
            (socket.AF_INET, "-4", "192.0.2.2", "198.51.100.86"),
            (socket.AF_INET6, "-6", "2001:db8:1::2", "2001:db8:3::85"),
        ):
            assert "dev nxphysical" in ip(switch, "route", "get", target)
            assert "dev nx-strict" in ip(switch, "route", "get", captured)
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(3)
                client.connect((target, 18080))
                client.sendall(b"kernel bypass")
                assert exact(client, len(b"kernel bypass"))==b"kernel bypass"
        guard = subprocess.run(["ip", "-4", "route", "get", "198.51.100.85"], capture_output=True, text=True, timeout=3)
        assert guard.returncode and "unreachable" in guard.stderr.lower(), guard
    print("TUN pre-match kernel exclusions and unreachable guard passed")


def check_crash_recovery(nexus_bin, config):
    def rules():
        return [ip(family, "rule", "show") for family in ("-4", "-6")]

    original = rules()
    reverse_path = Path("/proc/sys/net/ipv4/conf/nxphysical/rp_filter")
    original_reverse_path = reverse_path.read_text()
    command = ["stdbuf", "-oL", nexus_bin, "run", "--config", config]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as nexus:
        try:
            assert b"TUN listening on nx-strict" in line(nexus)
            assert original != rules()
        finally:
            if nexus.poll() is None:
                nexus.kill()
                nexus.wait(timeout=3)
        def cleaned():
            link = subprocess.run(["ip", "link", "show", "nx-strict"], capture_output=True, timeout=2)
            return link.returncode != 0 and rules() == original

        eventually(cleaned)
        assert reverse_path.read_text() == original_reverse_path
    with process(command) as nexus:
        assert b"TUN listening on nx-strict" in line(nexus)
    assert rules() == original and reverse_path.read_text() == original_reverse_path
    print("TUN strict-route cleanup and restart after proxy SIGKILL passed")
