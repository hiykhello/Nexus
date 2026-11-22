#!/usr/bin/env python3
"""Run batch 69's bounded protocol, configuration and lifecycle regressions."""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent


def collect(binary, evidence, persist_dns):
    scenarios = [
        ("stream-frames", ["httpupgrade_cli_faults.py", binary, "--evidence", evidence / "stream-frames.json"]),
        ("ordered-config", ["ordered_tcp_config_network.py", binary]),
        ("route-observation", ["proxy_route_observation_network.py", binary]),
        ("dns-bindings", ["proxy_dns_listener_reload_network.py", binary]),
        ("dns-policy", ["dns_rule_reload_network.py", binary]),
        ("dns-cache", ["dns_message_cache_cli.py", binary]),
        ("fakeip-state", ["dns_fakeip_cli_network.py", binary]),
        ("quic-route-generation", ["quic_proxy_route_reload_network.py", binary]),
        ("selector-state", ["selector_state_network.py", binary]),
        ("tcp-half-close-and-udp", ["connect_traffic_stats.py", binary, "--trojan"]),
    ]
    if persist_dns:
        scenarios.append(("dns-persistence", ["dns_message_persistence_network.py", binary]))
    return scenarios


def run_suite(binary, evidence, persist_dns):
    result = []
    for label, arguments in collect(binary, evidence, persist_dns):
        executable, *args = arguments
        command = [sys.executable, "-u", str(ROOT / executable), *map(str, args)]
        log = evidence / f"{label}.log"
        start = time.monotonic()
        with log.open("w") as output:
            try:
                status = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=180).returncode
            except subprocess.TimeoutExpired:
                status = 124
        result.append({"case": label, "argv": command, "status": status,
                       "seconds": round(time.monotonic() - start, 3), "log": log.name})
        print(f"{'PASS' if status == 0 else 'FAIL'} {shlex.join(command[2:])}", flush=True)
    with binary.open("rb") as executable:
        digest = hashlib.file_digest(executable, "sha256").hexdigest()
    (evidence / "summary.json").write_text(json.dumps({
        "binary_sha256": digest, "results": result,
    }, indent=2) + "\n")
    return any(case["status"] for case in result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda value: Path(value).resolve(strict=True))
    parser.add_argument("evidence", type=lambda value: Path(value).resolve())
    parser.add_argument("--dns-persistence", action="store_true")
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    raise SystemExit(run_suite(args.binary, args.evidence, args.dns_persistence))
