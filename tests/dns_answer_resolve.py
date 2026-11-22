"""Full ordinary-cache and local answers keep canonical names and TTL."""
import argparse
import pathlib
import subprocess
from dns_rule_support import DnsPeer

parser = argparse.ArgumentParser()
parser.add_argument("fixture", type=pathlib.Path)
args = parser.parse_args()
fixture = args.fixture.resolve()
for backend in ("epoll", "uring"):
    for mode in ("alias", "cache", "options", "local", "hosts", "mismatch", "conflict", "many", "cancel"):
        with DnsPeer() as peer:
            result = subprocess.run([fixture, str(peer.port), mode, backend], capture_output=True, timeout=5)
            if result.returncode:
                raise RuntimeError(f"{backend}/{mode}: exit={result.returncode}, stderr={result.stderr!r}, queries={peer.seen!r}")
            expected_name = "alias.rules.test" if mode in ("cache", "options") else "search.rules.test" if mode=="local" else \
                "pending.rules.test" if mode=="cancel" else mode+".rules.test"
            expected = [] if mode=="hosts" else [(expected_name, 1, "udp"), (expected_name, 28, "udp")]
            if mode=="options":
                expected.append((expected_name, 1, "udp"))
            if peer.seen != expected:
                raise RuntimeError(f"{backend}/{mode}: queries={peer.seen!r}, expected={expected!r}")
print("Full ordinary-cache and local answers, metadata, conflicts, limits and cancellation passed on both backends")
