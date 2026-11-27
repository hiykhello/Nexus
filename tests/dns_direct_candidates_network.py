#!/usr/bin/env python3
"""Check TLS DNS interface fallback using two reachable origin namespaces."""

from contextlib import ExitStack, contextmanager
from pathlib import Path
import os
import select
import socket
import subprocess
import sys
import tempfile
import time

from detour_network import reserve, running
from dns_encrypted_network import query
from network_selection_network import LINKS, TARGETS, default_route, peers, stall_primary_connects, status


@contextmanager
def dns_origin(fixture, pid, host, port, certificate, key, protocol):
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    with subprocess.Popen(["nsenter", "-t", str(pid), "-n", "--", fixture,
                           "-protocol", protocol, "-address", authority, "-cert", certificate,
                           "-key", key, "-trace-doh-pool"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0) as origin:
        def event(timeout):
            if not select.select([origin.stdout], [], [], timeout)[0]:
                raise RuntimeError(f"no DNS request reached {authority}")
            return origin.stdout.readline().decode().strip()
        try:
            if event(4) != authority:
                raise RuntimeError(f"origin did not listen on {authority}")
            yield event
        finally:
            if origin.poll() is None:
                origin.terminate()
            _, error = origin.communicate(timeout=5)
            if origin.returncode not in (-15, 0):
                raise RuntimeError(error)


def check(binary, fixture, protocol):
    transport = {"h2":"https", "h3":"https3", "quic":"quic"}[protocol]
    version = {"h2":"HTTP/2.0", "h3":"HTTP/3.0", "quic":"DoQ"}[protocol]
    http_path = ' path="/resolve?profile=edge"' if protocol != "quic" else ""
    ttl = 40 if protocol == "quic" else 29
    with ExitStack() as stack, tempfile.TemporaryDirectory(prefix="nexus-dns-networks-") as directory:
        root = Path(directory)
        namespaces = peers(stack, reserve())
        connect_port, front_port, dns_port = reserve(), reserve(), reserve()
        cert, key, config = (root / name for name in ("cert", "key", "nexus.kdl"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-days", "1", "-subj", "/CN=dns.test", "-addext", "subjectAltName=DNS:dns.test",
                        "-keyout", key, "-out", cert], check=True, capture_output=True)
        origins = {}
        for label, *_ in LINKS:
            for host in TARGETS:
                origins[label, host] = stack.enter_context(dns_origin(
                    fixture, namespaces[label], host, connect_port, cert, key, protocol))
        for i, host in enumerate(TARGETS):
            config.write_text(f'''schema-version 1
role "client"
control socket="{root}/control.sock"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front_port}; authentication "none"; }}
outbound "egress" type="direct" {{
    network strategy="prefer" type="ethernet" fallback="wifi" fallback-delay-ms=125 {{
        interface "primary" type="ethernet"
        interface "backup" type="wifi"
    }}
}}
dns {{
    listen host="127.0.0.1" port={dns_port}
    server "secure" type="{transport}" host="{host}" port={connect_port}{http_path} server-name="dns.test" ca-file="{cert}" detour="egress"
    rule domain-suffix="test" action="route" server="secure" timeout-ms=950
    final "secure"
    disable-cache #true
}}
routing {{ final "egress"; }}
''')

            def verify(which):
                with running([binary, "run", "--config", config], front_port, root / f"{which}-{i}.log"):
                    started = time.monotonic()
                    query(dns_port, which+".test", ttl=ttl)
                    if which == "backup":
                        assert .10 <= time.monotonic()-started < .95
                    fields = origins[which, host](2).split()
                    assert fields[:2] == ["request", which+".test"], fields
                    if protocol != "quic":
                        assert fields[2] == version, fields
                    _, source4, _, source6, _, _ = next(link for link in LINKS if link[0]==which)
                    if protocol == "h2":
                        assert fields[3].rsplit(":", 1)[0].strip("[]") == (source6 if ":" in host else source4), fields
                    else:
                        query(dns_port, which+"-again.test", ttl=ttl)
                        again = origins[which, host](2).split()
                        assert again[:2] == ["request", which+"-again.test"], again
                        connection_field = 2 if protocol == "quic" else 3
                        assert fields[connection_field] == again[connection_field], (fields, again)

                    if which == "primary" and protocol != "h2":
                        control = root / "control.sock"
                        generation = status(binary, control, 0, ("2", "2"))
                        default_route(LINKS[0], False)
                        try:
                            status(binary, control, generation, ("1", "1"))
                            query(dns_port, "withdrawn.test", ttl=ttl)
                            changed = origins["backup", host](2).split()
                            assert changed[:2] == ["request", "withdrawn.test"], changed
                        finally:
                            default_route(LINKS[0], True)

            verify("primary")
            with stall_primary_connects(namespaces["primary"], connect_port, udp=protocol != "h2"):
                verify("backup")
            for link in LINKS:
                default_route(link, False)
            try:
                with running([binary, "run", "--config", config], front_port, root / f"no-path-{i}.log"):
                    query(dns_port, "unavailable.test", code=2)
            finally:
                for link in LINKS:
                    default_route(link, True)
    print(f"Explicit DNS {version} used primary and backup interfaces within the query deadline over both families")


if __name__ == "__main__":
    binary, fixture = (str(Path(path).resolve(strict=True)) for path in sys.argv[1:3])
    protocol = "quic" if "--quic" in sys.argv[3:] else "h3" if "--h3" in sys.argv[3:] else "h2"
    namespace = os.stat("/proc/self/ns/net").st_ino
    if "--netns" not in sys.argv:
        subprocess.run(["unshare", "-Urn", "--", sys.executable, __file__, binary, fixture,
                        *sys.argv[3:], "--netns", str(namespace)], check=True)
    else:
        assert int(sys.argv[-1]) != namespace
        check(binary, fixture, protocol)
