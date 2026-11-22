#!/usr/bin/env python3
"""Verify that periodic rule refresh publishes only complete snapshots and cancels in flight."""
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile
import threading
import time

from dns_rule_support import DnsPeer, free_port, nexus_process
from named_http_rule_fetch import Origin, RULES
from udp_bind_port_network import certificate


def wait_until(condition, description, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(.01)
    raise RuntimeError(description)


def configure(root, selected, fallback, upstream, timeout=3000):
    config = root / "nexus.kdl"
    config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={free_port()}; authentication "none"; }}
outbound "direct" type="direct" {{ inet4-bind-address "127.0.0.4"; }}
outbound "edge" type="trojan" {{
  server host="upstream.test" port={upstream}
  bootstrap-resolver "fallback"
  detour "direct"
  authentication {{ password-file "{root / 'password'}"; }}
  tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
dns {{
  server "fallback" type="udp" host="127.0.0.1" port={fallback.port}
  server "selected" type="udp" host="127.0.0.1" port={selected.port}
  final "fallback"; strategy "ipv4_only";
}}
http-clients {{
  updates {{ outbound "edge"; domain-resolver "selected"; ca-file "{root / 'cert'}"; timeout-ms {timeout}; }}
}}
routing {{ default-outbound "direct"; }}
''')
    return config


def detour(root, upstream):
    config = root / "trojan.kdl"
    config.write_text(f'''schema-version 1
role "server"
inbound "edge" type="trojan" {{
  listen host="127.0.0.1" port={upstream}
  authentication {{ user "update" password-file="{root / 'password'}"; }}
  tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
}}
outbound "direct" type="direct" {{ inet4-bind-address "127.0.0.3"; }}
routing {{ default-outbound "direct"; }}
''')
    return config


def check(binary, root, selected, fallback):
    output = root / "rules.kdl"
    old = RULES.replace(b"fresh", b"prior")
    output.write_bytes(old)
    upstream = free_port()
    cfg = configure(root, selected, fallback, upstream, timeout=8000)
    with Origin(root) as origin, nexus_process(binary, detour(root, upstream)):
        def args(path):
            return [cfg, "updates", f"https://localhost:{origin.port}/{path}", "kdl", output]

        good = subprocess.run([binary, "rule", "fetch", *args("rules")], check=False,
                              capture_output=True, text=True, timeout=5)
        if good.returncode or output.read_bytes() != RULES:
            raise RuntimeError(f"TLS through the Trojan detour failed: {good.stderr}")
        if {name for name, *_ in selected.seen} != {"localhost"} or {name for name, *_ in fallback.seen} != {"upstream.test"}:
            raise RuntimeError(f"resolver dependencies were crossed: {selected.seen!r} {fallback.seen!r}")
        if [request[0] for request in origin.seen] != ["127.0.0.3"]:
            raise RuntimeError(f"request did not traverse the configured outbounds: {origin.seen!r}")

        output.write_bytes(old)
        observations = set()
        stopping = threading.Event()

        def read():
            while not stopping.wait(.002):
                observations.add(output.read_bytes())

        reader = threading.Thread(target=read)
        reader.start()
        try:
            wait_until(lambda: old in observations, "reader missed the old snapshot")
            before = len(origin.seen)
            pin = hashlib.sha256(RULES).hexdigest()
            with subprocess.Popen([binary, "rule", "watch", "100", *args("changing"), "--sha256", pin],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) as watcher:
                try:
                    wait_until(lambda: len(origin.seen) >= before + 1 and output.read_bytes() == old,
                               "failed refresh did not leave the old snapshot")
                    wait_until(lambda: RULES in observations, "valid refresh did not publish the new snapshot")
                    wait_until(lambda: len(origin.seen) >= before + 3, "third refresh did not reach the origin")
                    started = time.monotonic()
                    watcher.terminate()
                    _, warnings = watcher.communicate(timeout=2)
                    if watcher.returncode or time.monotonic() - started >= 2 or b"does not match" not in warnings:
                        raise RuntimeError(f"rule watch did not cancel cleanly: {warnings!r}")
                finally:
                    origin.release.set()
                    if watcher.poll() is None:
                        watcher.kill()
                        watcher.communicate(timeout=3)
            if observations != {old, RULES} or output.read_bytes() != RULES:
                raise RuntimeError(f"readers saw a partial rule snapshot: {observations!r}")
        finally:
            stopping.set()
            reader.join()

    (root / "password").write_text("incorrect")
    with Origin(root) as origin, nexus_process(binary, detour(root, upstream)):
        (root / "password").write_text("different")
        bad = subprocess.run([binary, "rule", "fetch", cfg, "updates", f"https://localhost:{origin.port}/rules",
                              "kdl", output], capture_output=True, text=True, timeout=5)
        if not bad.returncode or origin.seen or output.read_bytes() != RULES:
            raise RuntimeError(f"failed Trojan authentication escaped via direct egress: {bad.stderr}")


def main(binary):
    with tempfile.TemporaryDirectory() as folder, DnsPeer() as selected, DnsPeer() as fallback:
        root = Path(folder)
        certificate(root)
        password = root / "password"
        password.write_text("secret")
        password.chmod(0o600)
        check(binary, root, selected, fallback)
    print("Trojan detour, distinct DNS dependencies, failed refresh, concurrent atomic readers and SIGTERM passed")


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve(strict=True)))
