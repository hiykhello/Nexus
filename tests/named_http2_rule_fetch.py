#!/usr/bin/env python3
"""Exercise the production TLS HTTP/2 fetch path against Go net/http."""
from pathlib import Path
import hashlib
import select
import subprocess
import sys
import tempfile

from dns_rule_support import DnsPeer, free_port
from named_http_rule_fetch import conditional_peer_event, watch_conditional
from udp_bind_port_network import certificate


def main(binary, fixture=None):
    with tempfile.TemporaryDirectory() as folder, DnsPeer() as dns:
        root = Path(folder)
        certificate(root)
        output, source, config = (root / name for name in ("published.kdl", "rules.kdl", "config.kdl"))
        rules = b'schema-version 2\nkind "predicate"\nrule type="domain" value="h2.test"\n' + b"\n" * 140000
        source.write_bytes(rules)
        output.write_bytes(b"old snapshot")
        front = free_port()

        def configure(protocol, limit=200000, timeout=1700, header=""):
            config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
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
    ca-file "{root / 'cert'}"
    protocol "{protocol}"
    timeout-ms {timeout}
    max-response-bytes {limit}
    {header}
  }}
}}
routing {{ default-outbound "physical"; }}
''')

        def fetch(port, path, *options):
            return subprocess.run([binary, "rule", "fetch", config, "updates",
                                   f"https://localhost:{port}{path}", "kdl", output, *options],
                                  capture_output=True, text=True, timeout=5)

        configure("h2")
        if not fixture:
            failed = fetch(free_port(), "/rules")
            if not failed.returncode or "HTTP/2 rule fetch is unavailable" not in failed.stderr or dns.seen:
                raise RuntimeError("disabled h2 did not reject before DNS")
            if output.read_bytes() != b"old snapshot":
                raise RuntimeError("disabled h2 modified the output")
            print("HTTP/1.1-only build rejects h2 before DNS")
            return

        with subprocess.Popen([fixture, root / "cert", root / "key", source], stdout=subprocess.PIPE, bufsize=0) as peer:
            try:
                if not select.select([peer.stdout], [], [], 5)[0]:
                    raise RuntimeError("HTTP/2 fixture failed to start")
                port = int(peer.stdout.readline())
                expected = hashlib.sha256(rules).hexdigest()
                for protocol, path in (("h2", "/rules"), ("auto", "/stream")):
                    configure(protocol)
                    output.write_bytes(b"old snapshot")
                    good = fetch(port, path, "--sha256", expected)
                    if good.returncode or output.read_bytes() != rules:
                        raise RuntimeError(f"valid {protocol} {path} response failed: {good.stderr}")
                configure("h2", header='header "X-Nexus-Test" "custom value"; fingerprint "tls13-grease"; max-redirects 1')
                good = fetch(port, "/redirect")
                if good.returncode or output.read_bytes() != rules:
                    raise RuntimeError(f"configured HTTP/2 request header missing: {good.stderr}")
                opened = []
                for label in (b"redirect", b"final"):
                    if not select.select([peer.stdout], [], [], 3)[0]:
                        raise RuntimeError(f"HTTP/2 peer did not observe {label!r}")
                    tag, remote = peer.stdout.readline().split()
                    if tag != label:
                        raise RuntimeError(f"unexpected HTTP/2 peer event {tag!r}")
                    opened.append(remote)
                if opened[0] != opened[1]:
                    raise RuntimeError(f"HTTP/2 redirect opened a second TLS connection: {opened!r}")
                if not dns.seen:
                    raise RuntimeError("named HTTP/2 client skipped the resolver")
                configure("h2")
                for path in ("/not-found", "/reset", "/short", "/stream-limit", "/encoded"):
                    if not fetch(port, path).returncode or output.read_bytes() != rules:
                        raise RuntimeError(f"invalid HTTP/2 response replaced the rules: {path}")
                configure("h2", limit=512)
                if not fetch(port, "/rules").returncode or output.read_bytes() != rules:
                    raise RuntimeError("oversized HTTP/2 Content-Length replaced the rules")
                configure("h2", timeout=350)
                if not fetch(port, "/timeout").returncode or output.read_bytes() != rules:
                    raise RuntimeError("timed-out HTTP/2 response replaced the rules")
                configure("h2")
                watch_conditional(binary, config, output, port, rules, lambda: conditional_peer_event(peer))
            finally:
                peer.terminate()
                peer.wait(timeout=5)
        print("HTTP/2 TLS ALPN, flow control, trailers, SHA-256 and error handling passed")


if __name__ == "__main__":
    main(*(str(Path(item).resolve(strict=True)) for item in sys.argv[1:]))
