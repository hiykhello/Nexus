#!/usr/bin/env python3
"""Verify live route generations through production listeners and atomic rule publication."""
import base64
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from dns_rule_support import DnsPeer, Echo, connect, datagram_request, exact, free_port, nexus_process, stream_request, udp_client
from named_http_rule_fetch import Origin, RULES
from proxy_listener_reload_network import reload as reload_listeners
from udp_bind_port_network import certificate


def configure(root, ports, dns, ordered, use_fetch):
    restrictions = '''
  tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {
    rule action="reject" rule-set="primary"
    rule action="reject" rule-set="secondary"
    rule action="resolve"
    rule action="route" outbound="direct"
  }''' if ordered else '''
  rule kind="rule-set" value="primary" outbound="deny"
  rule kind="rule-set" value="secondary" outbound="deny"'''
    http_client = f'''
http-clients {{
  updates {{ outbound "direct"; domain-resolver "dns"; ca-file "{root / 'cert'}"; }}
}}''' if use_fetch else ""
    path = root / "config.kdl"
    path.write_text(f'''schema-version 1
role "client"
workers 2
inbound "first" type="socks5" {{ listen host="127.0.0.1" port={ports[0]}; authentication "none"; }}
inbound "second" type="socks5" {{ listen host="127.0.0.1" port={ports[1]}; authentication "none"; }}
outbound "direct" type="direct"
outbound "deny" type="block"
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns}; final "dns"; strategy "ipv4_only"; }}
routing {{
  rule-set "primary" path="primary.kdl" format="kdl"
  rule-set "secondary" path="secondary.beve" format="beve"
  {restrictions}
  default-outbound "direct"
}}
{http_client}
''')
    return path


def replace(path, data):
    candidate = path.with_suffix(".candidate")
    candidate.write_bytes(data)
    candidate.replace(path)


def publish(binary, root, config, destination, use_fetch):
    if not use_fetch:
        replace(destination, RULES)
        return
    with Origin(root) as origin:
        digest = hashlib.sha256(RULES).hexdigest()
        result = subprocess.run([binary, "rule", "fetch", config, "updates", f"https://localhost:{origin.port}/rules",
                                 "kdl", destination, "--sha256", digest],
                                capture_output=True, text=True, timeout=5)
        if result.returncode or destination.read_bytes() != RULES or len(origin.seen) != 1:
            raise RuntimeError(f"HTTPS rule publication failed: {result.stderr}")


def reload_rules(process, accepted, reason=b""):
    reload_listeners(process, failure=None if accepted else reason)


def greet(client):
    client.sendall(b"\x05\x01\x00")
    if exact(client, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting failed")


def pending_request(client, port, allowed):
    name = b"fresh.test"
    client.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", port))
    reply = exact(client, 4)
    if (reply[1] == 0) != allowed or reply[3] not in (1, 4):
        raise RuntimeError(f"pending SOCKS session saw the wrong rule generation: {reply!r}")
    exact(client, 6 if reply[3] == 1 else 18)
    if allowed:
        client.sendall(b"previous generation")
        if exact(client, 19) != b"previous generation":
            raise RuntimeError("previous generation did not relay the pending stream")


def check(binary, root, dns, echo, secondary_rules, ordered, use_fetch):
    primary = root / "primary.kdl"
    secondary = root / "secondary.beve"
    old_rules = RULES.replace(b"fresh.test", b"unused.test")
    primary.write_bytes(old_rules)
    secondary.write_bytes(secondary_rules)
    ports = free_port(), free_port()
    config = configure(root, ports, dns.port, ordered, use_fetch)
    with nexus_process(binary, config, listeners=2) as process:
        for front in ports:
            stream_request(front, echo.port, "fresh.test")
        publish(binary, root, config, primary, use_fetch)

        secondary.unlink()
        reload_rules(process, False)
        for front in ports:
            stream_request(front, echo.port, "fresh.test")
        replace(secondary, b"not a predicate rule")
        reload_rules(process, False)
        with secondary.open("wb") as oversized:
            oversized.truncate(8 * 1024 * 1024 + 1)
        reload_rules(process, False)
        for front in ports:
            stream_request(front, echo.port, "fresh.test")
        replace(secondary, secondary_rules)

        with connect(ports[0]) as previous, udp_client(ports[1]) as (old_udp, old_relay):
            greet(previous)
            reload_rules(process, True)
            for _ in range(12):
                for front in ports:
                    stream_request(front, echo.port, "fresh.test", success=False)
            pending_request(previous, echo.port, allowed=True)
            datagram_request(old_udp, old_relay, echo.port, "fresh.test")
            with udp_client(ports[1]) as (new_udp, new_relay):
                datagram_request(new_udp, new_relay, echo.port, "fresh.test", success=False)

        with connect(ports[1]) as previous:
            greet(previous)
            replace(primary, old_rules)
            reload_rules(process, True)
            pending_request(previous, echo.port, allowed=False)
            for front in ports:
                stream_request(front, echo.port, "fresh.test")
                stream_request(front, echo.port, "secondary.test", success=False)



def check_ss_udp_boundary(binary, root, dns, echo):
    key = root / "ss-key"
    key.write_bytes(base64.b64encode(bytes(range(16))))
    key.chmod(0o600)
    primary = root / "primary.kdl"
    for native_udp in (True, False):
        replace(primary, RULES.replace(b"fresh.test", b"unused.test"))
        ports = free_port(), free_port()
        cfg = configure(root, ports, dns.port, ordered=True, use_fetch=False)
        extra = f'''inbound "ss" type="shadowsocks" {{
  listen host="127.0.0.1" port={free_port()}
  method "2022-blake3-aes-128-gcm"
  key-file "{key}"
}}
'''
        configuration = cfg.read_text().replace('role "client"', 'role "server"').replace(
            'outbound "direct" type="direct"', extra + 'outbound "direct" type="direct"')
        if not native_udp:
            configuration = configuration.replace("udp=#true", "udp=#false")
        cfg.write_text(configuration)
        with nexus_process(binary, cfg, listeners=3) as process:
            replace(primary, RULES)
            if native_udp:
                assert reload_listeners(process) == 2
            else:
                reload_rules(process, True)
            for front in ports:
                stream_request(front, echo.port, "fresh.test", success=False)


def main(binary, use_fetch):
    with tempfile.TemporaryDirectory() as directory, DnsPeer() as dns, Echo() as echo:
        root = Path(directory)
        source, converted = root / "convert.kdl", root / "converted.beve"
        source.write_bytes(RULES.replace(b"fresh.test", b"secondary.test"))
        subprocess.run([binary, "rule", "convert", "kdl", "beve", source, converted],
                       check=True, capture_output=True, timeout=5)
        secondary_rules = converted.read_bytes()
        if use_fetch:
            certificate(root)
        for ordered in (False, True):
            check(binary, root, dns, echo, secondary_rules, ordered, use_fetch)
        if use_fetch:
            check_ss_udp_boundary(binary, root, dns, echo)
    print("Indexed and ordered TCP/UDP reload, two listeners and workers, old and new generations, rejection and recovery passed")


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve(strict=True)), "--without-fetch" not in sys.argv[2:])
