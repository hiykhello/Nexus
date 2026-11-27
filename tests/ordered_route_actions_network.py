#!/usr/bin/env python3
"""Exercise ordered connection deadlines and local DNS on the SOCKS5 relay."""
from pathlib import Path
import select
import socket
import struct
import sys
import tempfile
import time

from dns_rule_support import DnsPeer, Echo, free_port, nexus_process, stream_request, udp_client, wire_name


def query(name, identifier):
    return struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0) + wire_name(name) + struct.pack("!HH", 1, 1)


def ip_target(port):
    return b"\0\0\0\1" + socket.inet_aton("127.0.0.1") + struct.pack("!H", port)


def domain_target(name, port):
    return b"\0\0\0\3" + bytes([len(name)]) + name.encode() + struct.pack("!H", port)


def main(binary):
    with tempfile.TemporaryDirectory() as folder, DnsPeer() as dns, Echo() as echo, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forbidden:
        root = Path(folder)
        front = free_port()
        forbidden.bind(("127.0.0.1", 0))
        forbidden_port = forbidden.getsockname()[1]
        dns.delays["slow.test", 1] = .65
        dns.drop.add(("absent.test", 1))
        (root / "slow.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="slow.test"\n')
        (root / "dns.kdl").write_text(f'schema-version 2\nkind "predicate"\nrule type="port" value="{forbidden_port}"\n')
        config = root / "config.kdl"
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
dns {{
  server "peer" type="udp" host="127.0.0.1" port={dns.port}
  strategy "ipv4_only"
  rule domain="local.test" inbound="local" network="udp" action="predefined" {{
    record section="answer" name="@" type=1 address="192.0.2.9" ttl=60
  }}
  final "peer"
}}
routing {{
  rulesets {{
      "slow" path="slow.kdl" format="kdl"
      "dns" path="dns.kdl" format="kdl"
  }}
  tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{
    rule action="route-options" rule-set="slow" connect-timeout-ms=220
    rule action="route-options" rule-set="slow" connect-timeout-ms=3000
    rule action="route-options" rule-set="dns" connect-timeout-ms=300
    rule action="hijack-dns" rule-set="dns"
    rule action="resolve"
    rule action="route" outbound="direct"
  }}
  final "direct"
}}
''')
        with nexus_process(binary, config):
            started = time.monotonic()
            stream_request(front, echo.port, "slow.test", success=False)
            if time.monotonic() - started >= .6:
                raise RuntimeError("later route-options extended the TCP deadline")
            if ("slow.test", 1, "udp") not in dns.seen or echo.accepted:
                raise RuntimeError("TCP deadline did not cover the upstream DNS lookup")
            time.sleep(.5)
            stream_request(front, echo.port, "normal.test")
            with udp_client(front) as (client, relay):
                client.sendto(domain_target("slow.test", echo.port) + b"late", relay)
                if select.select([client], [], [], .8)[0] or b"late" in echo.received:
                    raise RuntimeError("UDP target received traffic after its deadline")
                for prefix, identifier in (
                    (ip_target(forbidden_port), 0x1234),
                    (domain_target("resolver-destination.test", forbidden_port), 0x2345),
                ):
                    request = query("local.test", identifier)
                    client.sendto(prefix + request, relay)
                    response = client.recv(1024)
                    if not response.startswith(prefix):
                        raise RuntimeError("DNS reply changed the SOCKS target")
                    wire = response[len(prefix):]
                    if (wire[:2] != request[:2] or wire[4:8] != b"\0\1\0\1" or
                        wire[12:len(request)] != request[12:] or wire[-4:] != socket.inet_aton("192.0.2.9")):
                        raise RuntimeError("DNS reply changed the transaction, question or predefined response")
                if any(name in ("local.test", "resolver-destination.test") for name, *_ in dns.seen):
                    raise RuntimeError("local DNS action delegated the request")
                address = ip_target(forbidden_port)
                client.sendto(address + b"invalid DNS", relay)
                client.sendto(address + query("absent.test", 0x3456), relay)
                if select.select([client, forbidden], [], [], .55)[0]:
                    raise RuntimeError("invalid or expired DNS leaked or returned a late reply")
                if ("absent.test", 1, "udp") not in dns.seen:
                    raise RuntimeError("DNS action did not reach its configured upstream")
                address = ip_target(echo.port)
                client.sendto(address + b"next", relay)
                if client.recv(1024) != address + b"next":
                    raise RuntimeError("UDP association could not continue after DNS timeout")
        print("Ordered TCP/UDP deadlines, DNS interception, source, failure and recovery passed")


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve(strict=True)))
