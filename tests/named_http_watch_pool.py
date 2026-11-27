from pathlib import Path
import os
import select
import subprocess
import sys
import tempfile
import time

from dns_rule_support import DnsPeer, free_port
from named_http_rule_fetch import RULES
from udp_bind_port_network import certificate


def check(binary, protocol, fixture):
    with tempfile.TemporaryDirectory() as folder, DnsPeer() as dns:
        root = Path(folder)
        wrong = root / "wrong"
        wrong.mkdir()
        certificate(root)
        certificate(wrong)
        cert, key, source, trust, config, output = (
            root / name for name in ("cert", "key", "rules", "trust", "config", "output")
        )
        source.write_bytes(RULES)

        def update_trust(value):
            candidate = root / "next"
            candidate.write_bytes(value.read_bytes())
            candidate.replace(trust)

        update_trust(cert)
        config.write_text(f"""schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={free_port()}; authentication "none"; }}
outbound "physical" type="direct" {{ inet4-bind-address "127.0.0.2"; }}
dns {{
  server "bootstrap" type="udp" host="127.0.0.1" port={dns.port}
  final "bootstrap"
  strategy "ipv4_only"
}}
http-clients {{
  updates {{
    outbound "physical"
    domain-resolver "bootstrap"
    ca-file "{trust}"
    protocol "{protocol}"
    timeout-ms 1200
    max-redirects 1
    header "X-Nexus-Test" "custom value"
  }}
}}
routing {{ final "physical"; }}
""")
        with subprocess.Popen([fixture, cert, key, source], stdout=subprocess.PIPE, bufsize=0,
                              stderr=subprocess.PIPE, env=dict(os.environ, NEXUS_TEST_MAX_PACKET="1500")) as peer:
            def line():
                if not select.select([peer.stdout], [], [], 4)[0]:
                    raise RuntimeError("peer did not observe the request")
                return peer.stdout.readline().strip()

            def round_trip():
                redirect = line().split()
                final = line().split()
                if redirect[0] != b"redirect" or final[0] != b"final" or redirect[1] != final[1]:
                    raise RuntimeError(f"unexpected redirect connection events {redirect!r}, {final!r}")
                return redirect[1]

            try:
                port = int(line().rsplit(b":", 1)[-1])
                args = [binary, "rule", "watch", "500", config, "updates",
                        f"https://localhost:{port}/redirect", "kdl", output]
                with subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as watcher:
                    try:
                        def published(previous=None):
                            deadline = time.monotonic() + .35
                            while time.monotonic() < deadline:
                                if output.exists():
                                    current = output.stat()
                                    if (previous is None or current.st_ino != previous.st_ino) and output.read_bytes() == RULES:
                                        return current
                                time.sleep(.005)
                            raise RuntimeError("watcher did not publish the complete rules")

                        old = round_trip()
                        first = published()
                        another = round_trip()
                        if old != another:
                            raise RuntimeError(f"{protocol} watcher opened distinct connections {old!r}, {another!r}")
                        before = published(first)
                        update_trust(wrong / "cert")
                        if select.select([peer.stdout], [], [], 1.5)[0]:
                            raise RuntimeError(f"{protocol} used HTTP after trust rotation: {line()!r}")
                        after = output.stat()
                        if (after.st_ino, after.st_mtime_ns) != (before.st_ino, before.st_mtime_ns):
                            raise RuntimeError("failed certificate verification replaced published rules")
                        update_trust(cert)
                        new = round_trip()
                        if old == new:
                            raise RuntimeError("restored trust resumed an obsolete connection")
                    finally:
                        watcher.terminate()
                        _, warnings = watcher.communicate(timeout=5)
                        if watcher.returncode:
                            raise RuntimeError(f"watcher could not stop: {warnings!r}")
                    if b"certificate verification failed" not in warnings and b"HTTP/3" not in warnings:
                        raise RuntimeError(f"trust rejection did not produce an error: {warnings!r}")
            finally:
                peer.terminate()
                peer.communicate(timeout=5)
    print(f"{protocol} retained an authenticated connection across refreshes, rejected rotated trust, and recovered on a fresh connection")


if __name__ == "__main__":
    check(*(os.path.abspath(arg) if i != 1 else arg for i, arg in enumerate(sys.argv[1:])))
