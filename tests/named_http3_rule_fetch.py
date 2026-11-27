#!/usr/bin/env python3
"""Check ordinary HTTP/3, ECH, UDP egress and publication through production CLI."""
from pathlib import Path
import hashlib
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

from dns_rule_support import DnsPeer, free_port
from named_http_rule_fetch import Origin, RULES, conditional_peer_event, watch_conditional
from quic_ech_cli import generate
from tuic_singbox import stop_proc
from udp_bind_port_network import certificate


def wait_for(predicate, detail):
    deadline = time.monotonic() + 4
    while not predicate():
        if time.monotonic() >= deadline:
            raise RuntimeError(detail)
        time.sleep(.01)


def automatic(binary, fixture):
    with tempfile.TemporaryDirectory() as folder, DnsPeer() as dns, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dead:
        root = Path(folder)
        certificate(root)
        output, config, source = (root / name for name in ("published.kdl", "nexus.kdl", "rules"))
        h3_rules = RULES.replace(b"fresh.test", b"quic.test")
        source.write_bytes(h3_rules)
        dead.bind(("127.0.0.1", 0))
        dead.settimeout(4)
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={free_port()}; authentication "none"; }}
outbound "physical" type="direct" {{ inet4-bind-address "127.0.0.2"; }}
dns {{ server "resolver" type="udp" host="127.0.0.1" port={dns.port}; final "resolver"; strategy "ipv4_only"; }}
http-clients {{
  updates {{
    outbound "physical"; domain-resolver "resolver"; ca-file "{root / 'cert'}";
    protocol "auto"; timeout-ms 1200;
  }}
}}
routing {{ final "physical"; }}
''')
        env = dict(os.environ, NEXUS_TEST_MAX_PACKET="1500")
        with Origin(root) as origin, subprocess.Popen([fixture, root / "cert", root / "key", source], env=env,
                                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE) as peer:
            try:
                if not select.select([peer.stdout], [], [], 5)[0]:
                    raise RuntimeError("HTTP/3 peer did not start")
                port = int(peer.stdout.readline().decode().strip().rsplit(":", 1)[1])
                args = [binary, "rule", "watch", "150", config, "updates",
                        f"https://localhost:{origin.port}/rules", "kdl", output]
                origin.alternative_port = port
                with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as watcher:
                    try:
                        wait_for(lambda: output.exists() and output.read_bytes() == h3_rules,
                                 "watcher did not publish the HTTP/3 alternative's body")
                        if len(origin.seen) != 1:
                            raise RuntimeError(f"watcher retried the TCP origin: {origin.seen!r}")
                        if not select.select([peer.stdout], [], [], 2)[0] or peer.stdout.readline() != b"rules request\n":
                            raise RuntimeError("no verified QUIC origin request")
                    finally:
                        stop_proc(watcher)

                before = len(origin.seen)
                origin.alternative_port = dead.getsockname()[1]
                with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as watcher:
                    try:
                        initial, source_address = dead.recvfrom(1500)
                        if len(initial) < 1200 or source_address[0] != "127.0.0.2":
                            raise RuntimeError("auto did not use the configured UDP egress")
                        wait_for(lambda: len(origin.seen) >= before+2 and output.read_bytes() == RULES,
                                 "watcher did not fall back to the same named client over TCP")
                    finally:
                        stop_proc(watcher)
            finally:
                stop_proc(peer)
    print("Named auto watcher discovered authenticated same-host HTTP/3 and fell back to TCP after a silent alternative")


def main(binary, fixture):
    with tempfile.TemporaryDirectory() as folder, DnsPeer() as dns:
        root = Path(folder)
        certificate(root)
        output, config, source = (root / name for name in ("published.kdl", "nexus.kdl", "rules"))
        rules = RULES + b"//" + b"x" * 49152 + b"\n"
        source.write_bytes(rules)
        output.write_bytes(b"old version")
        front = free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.2", 0))
            source_port = reservation.getsockname()[1]

        def configure(ech_file, timeout=900, header=""):
            ech_option = f'ech-config-file "{ech_file}";' if ech_file else ""
            config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "physical" type="direct" {{ inet4-bind-address "127.0.0.2"; udp-bind-port {source_port}; }}
dns {{ server "resolver" type="udp" host="127.0.0.1" port={dns.port}; final "resolver"; strategy "ipv4_only"; }}
http-clients {{
  updates {{
    outbound "physical"; domain-resolver "resolver"; ca-file "{root / 'cert'}";
    protocol "h3"; timeout-ms {timeout}; max-response-bytes 64000; max-udp-payload-size 1200;
    {ech_option}
    {header}
  }}
}}
routing {{ final "physical"; }}
''')

        if fixture is None:
            configure(None)
            rejected = subprocess.run([binary, "rule", "fetch", config, "updates",
                                       "https://localhost:443/rules", "kdl", output],
                                      capture_output=True, text=True, timeout=5)
            if (not rejected.returncode or "HTTP/3 rule fetch is unavailable" not in rejected.stderr
                    or dns.seen or output.read_bytes() != b"old version"):
                raise RuntimeError(f"HTTP/3-disabled graph reached network or output: {rejected.stderr}")
            print("HTTP/3-disabled graph rejected an explicit h3 client before I/O")
            return

        ech, keys = generate(root, "correct")
        wrong, _ = generate(root, "wrong")
        env = dict(os.environ, NEXUS_TEST_ECH_KEYS=str(keys), NEXUS_TEST_SOURCE_PORT=str(source_port))
        with subprocess.Popen([fixture, root / "cert", root / "key", source], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0) as peer:
            try:
                if not select.select([peer.stdout], [], [], 5)[0]:
                    raise RuntimeError("HTTP/3 peer did not start")
                address = peer.stdout.readline().decode().strip()
                if not address.startswith("127.0.0.1:"):
                    raise RuntimeError(f"HTTP/3 peer listener is missing: {address!r}")
                port = int(address.rsplit(":", 1)[1])

                def fetch(path, *options):
                    args = [binary, "rule", "fetch", config, "updates", f"https://localhost:{port}{path}",
                            "kdl", output, *options]
                    return subprocess.run(args, capture_output=True, text=True, timeout=5)

                configure(ech)
                good = fetch("/rules", "--sha256", hashlib.sha256(rules).hexdigest())
                if good.returncode or output.read_bytes() != rules:
                    raise RuntimeError(f"authenticated HTTP/3 rules failed: {good.stderr}")
                if not select.select([peer.stdout], [], [], 2)[0] or peer.stdout.readline() != b"rules request\n":
                    raise RuntimeError("HTTP/3 peer did not record the authenticated rules request")
                if not dns.seen or any(item != ("localhost", 1, "udp") for item in dns.seen):
                    raise RuntimeError(f"wrong resolver behavior: {dns.seen!r}")
                configure(ech, header='header "X-Nexus-Test" "custom value"; fingerprint "tls13-grease"; '
                                      'disable-path-mtu-discovery #true; max-redirects 1;')
                good = fetch("/redirect")
                if good.returncode or output.read_bytes() != rules:
                    raise RuntimeError(f"configured HTTP/3 request header missing: {good.stderr}")
                connections = []
                for label in (b"redirect", b"final"):
                    if not select.select([peer.stdout], [], [], 3)[0]:
                        raise RuntimeError(f"HTTP/3 peer did not report {label!r}")
                    tag, connection = peer.stdout.readline().split()
                    if tag != label or not connection.isdigit():
                        raise RuntimeError(f"unexpected HTTP/3 event {(tag, connection)!r}")
                    connections.append(connection)
                if connections[0] != connections[1]:
                    raise RuntimeError(f"HTTP/3 redirect opened a second QUIC connection: {connections!r}")
                configure(ech, timeout=1700)
                config.write_text(config.read_text().replace('strategy "ipv4_only"', 'strategy "prefer_ipv6"'))
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as silent:
                    silent.bind(("::1", port))
                    silent.settimeout(1)
                    command = [binary, "rule", "fetch", config, "updates",
                               f"https://localhost:{port}/rules", "kdl", output]
                    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as client:
                        try:
                            packet, _ = silent.recvfrom(1500)
                            if len(packet) < 1200 or not packet[0] & 0x80:
                                raise RuntimeError("first DNS candidate did not receive a QUIC Initial")
                            _, errors = client.communicate(timeout=3)
                            if client.returncode or output.read_bytes() != rules:
                                raise RuntimeError(f"HTTP/3 did not reach the second DNS candidate: {errors!r}")
                        finally:
                            stop_proc(client)
                if not select.select([peer.stdout], [], [], 2)[0] or peer.stdout.readline() != b"rules request\n":
                    raise RuntimeError("second DNS candidate did not receive the request")
                configure(ech)
                for path in ("/status", "/short", "/encoded", "/stream-limit", "/timeout"):
                    failed = fetch(path)
                    if not failed.returncode or output.read_bytes() != rules:
                        raise RuntimeError(f"{path} published incomplete HTTP/3 rules: {failed.stderr}")
                for rejected in (None, wrong):
                    configure(rejected)
                    failed = fetch("/rules")
                    if not failed.returncode or output.read_bytes() != rules:
                        raise RuntimeError(f"HTTP/3 accepted ECH configuration {rejected}")
                configure(ech, timeout=8000)
                args = [binary, "rule", "watch", "100", config, "updates",
                        f"https://localhost:{port}/watch", "kdl", output]
                with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as watcher:
                    try:
                        if (not select.select([peer.stdout], [], [], 5)[0]
                                or peer.stdout.readline() != b"watch request\n"):
                            raise RuntimeError("HTTP/3 watcher did not reach the response stage")
                        watcher.send_signal(signal.SIGINT)
                        _, warnings = watcher.communicate(timeout=2)
                        if watcher.returncode or output.read_bytes() != rules:
                            raise RuntimeError(f"HTTP/3 watcher did not cancel cleanly: {warnings!r}")
                    finally:
                        stop_proc(watcher)
                configure(ech)
                watch_conditional(binary, config, output, port, rules, lambda: conditional_peer_event(peer))
            finally:
                stop_proc(peer)
                diagnostics = peer.stderr.read()
                if b"received UDP payload" in diagnostics:
                    raise RuntimeError(f"client exceeded the configured UDP cap: {diagnostics!r}")
    print("HTTP/3 GET, ECH acceptance and rejection, bound UDP, datagram cap, response limits, timeout and SIGINT cancellation passed")


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    fixture = str(Path(sys.argv[2]).resolve(strict=True)) if len(sys.argv) > 2 else None
    if "--auto" in sys.argv[3:]:
        automatic(binary, fixture)
    else:
        main(binary, fixture)
