import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
import os

from dns_rule_support import free_port, nexus_process, udp_client
from tun_route_reload_network import ip


def vectors(fixture):
    payload = subprocess.run([fixture, "--protocol-vectors"], check=True, capture_output=True).stdout
    values = []
    while payload:
        size = int.from_bytes(payload[:2], "big")
        if not size or len(payload) < size + 2:
            raise RuntimeError("invalid QUIC protocol fixture")
        values.append(payload[2:size + 2])
        payload = payload[size + 2:]
    return values


def main(binary, fixture, enabled=True):
    plain, ech, broken, first, second = vectors(fixture)
    with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin:
        root = Path(directory)
        origin.bind(("127.0.0.1", 0))
        (root / "domain.kdl").write_text(
            'schema-version 2\nkind "predicate"\nrule type="domain" value="example.com"\n')
        (root / "quic.kdl").write_text(
            'schema-version 2\nkind "predicate"\nrule type="protocol" value="quic"\n')
        front = free_port()
        config = root / "config.kdl"
        template = f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
routing {{
    rulesets {{
        DOMAIN_SET
        quic path="quic.kdl" format="kdl"
    }}
    tcp-program sniff-timeout-ms=200 unknown="skip" udp=#true {{
        rule action="sniff"
        KEEP_DOMAIN
        rule action="reject" rule-set="quic"
        rule action="route" outbound="direct"
    }}
    final "direct"
}}
'''
        header = b"\0\0\0\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", origin.getsockname()[1])

        def send(client, relay, value):
            client.sendto(header + value, relay)

        def receive(value):
            origin.settimeout(2)
            data, _ = origin.recvfrom(4096)
            if data != value:
                raise RuntimeError(f"unexpected forwarded datagram of {len(data)} bytes")

        config.write_text(template.replace("DOMAIN_SET", "").replace("KEEP_DOMAIN", ""))
        with nexus_process(binary, str(config)), udp_client(front) as (client, relay):
            for value in (plain, ech, broken, first, second, b"UDP control"):
                send(client, relay, value)
            if enabled:
                receive(broken)
            else:
                for value in (plain, ech, broken, first, second):
                    receive(value)
            receive(b"UDP control")
        if enabled:
            config.write_text(template.replace("DOMAIN_SET", 'domain path="domain.kdl" format="kdl"')
                .replace("KEEP_DOMAIN", 'rule action="route" rule-set="domain" domain-source="sniffed" outbound="direct"'))
            with nexus_process(binary, str(config)), udp_client(front) as (client, relay):
                for value in (plain, ech, b"UDP control"):
                    send(client, relay, value)
                receive(plain)
                receive(b"UDP control")
    print("SOCKS UDP protocol rule classified QUIC independently of SNI" if enabled else
          "QUIC predicate remained unknown with sniffing disabled")


def tun(binary, fixture, parent_namespace=None):
    binary, fixture = (str(Path(path).resolve(strict=True)) for path in (binary, fixture))
    namespace = os.stat("/proc/self/ns/net").st_ino
    if parent_namespace is None:
        subprocess.run(["unshare", "-Urn", "--", sys.executable, __file__, binary, fixture,
                        "--tun", str(namespace)], check=True)
        return
    if namespace == int(parent_namespace):
        raise RuntimeError("expected an isolated TUN namespace")
    ip("link", "set", "lo", "up")
    address = "198.51.100.10"
    destination = address + "/32"
    ip("addr", "add", destination, "dev", "lo")
    ip("route", "add", "local", destination, "dev", "lo", "table", "100", "src", "127.0.0.1")
    ip("rule", "del", "priority", "0")
    ip("rule", "add", "priority", "1", "fwmark", "43", "lookup", "100")
    ip("rule", "add", "priority", "2", "to", destination, "table", "main")
    ip("rule", "add", "priority", "3", "lookup", "local")

    plain, ech, broken, *_ = vectors(fixture)
    with tempfile.TemporaryDirectory() as directory, socket.socket(type=socket.SOCK_DGRAM) as origin:
        root = Path(directory)
        origin.bind((address, 0))
        origin.settimeout(3)
        (root / "quic.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="protocol" value="quic"\n')
        config = root / "config.kdl"
        config.write_text("""schema-version 1
role "client"
inbounds {
  tun "host" {
    interface-name "nx-sniff"
    inet4-address "10.91.0.1/30"
    socket-mark 43
  }
}
outbound "physical" type="direct"
routing {
  rulesets { quic path="quic.kdl" format="kdl"; }
  tcp-program sniff-timeout-ms=200 unknown="skip" udp=#true {
    rule action="sniff"
    rule action="reject" rule-set="quic"
    rule action="route" outbound="physical"
  }
  final "physical"
}
""")
        with nexus_process(binary, str(config)):
            ip("route", "add", destination, "dev", "nx-sniff", "src", "10.91.0.1")
            for payload in (plain, ech, broken, b"UDP control"):
                with socket.socket(type=socket.SOCK_DGRAM) as client:
                    client.sendto(payload, origin.getsockname())
            for expected in (broken, b"UDP control"):
                data, _ = origin.recvfrom(4096)
                if data != expected:
                    raise RuntimeError(f"TUN protocol rule forwarded a matched QUIC request ({len(data)} bytes)")
    print("Routed TUN applied QUIC classification with ECH and passed unclassified traffic")


if __name__ == "__main__":
    if "--tun" in sys.argv[3:]:
        tun(*sys.argv[1:3], *sys.argv[4:5])
    else:
        main(sys.argv[1], sys.argv[2], "--off" not in sys.argv[3:])
