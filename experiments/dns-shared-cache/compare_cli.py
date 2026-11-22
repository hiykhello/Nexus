#!/usr/bin/env python3
"""Compare production CLI binaries with the same fixed-offer network workload."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("baseline", type=Path)
parser.add_argument("candidate", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--seconds", type=int, default=10)
parser.add_argument("--rate", type=int, default=400)
parser.add_argument("--rounds", type=int, default=3)
parser.add_argument("--local-dns", action="store_true")
parser.add_argument("--rule-count", type=int, default=0)
parser.add_argument("--logical-rules", action="store_true")
parser.add_argument("--proxy-cpus", default="0-5")
parser.add_argument("--harness-cpus", default="6,7")
parser.add_argument("--singbox-cpus", default="8-11")
args = parser.parse_args()
if args.rounds < 1:
    parser.error("rounds must be positive")
binaries = {"shared": args.baseline.resolve(strict=True), "coordinator": args.candidate.resolve(strict=True)}
script = Path(__file__).resolve().parent / "proxy_group_bench_netns.sh"
scenarios = ("hot", "uniform", "disjoint", "expiry")
failures = 0
with args.output.open("x", encoding="utf-8") as output:
    metadata = {"record": "metadata", "unix_time": time.time(), "kernel": platform.release(),
                "cpu_affinity": sorted(os.sched_getaffinity(0)), "seconds": args.seconds,
                "rate": args.rate, "rounds": args.rounds, "local_dns": args.local_dns, "rule_count": args.rule_count,
                "logical_rules": args.logical_rules,
                "binaries": {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                             for name, path in binaries.items()}}
    output.write(json.dumps(metadata, sort_keys=True) + "\n")
    output.flush()
    for round_index in range(args.rounds):
        reverse = round_index % 2 == 1
        for scenario in reversed(scenarios) if reverse else scenarios:
            for mode in ("coordinator", "shared") if reverse else ("shared", "coordinator"):
                command = ["unshare", "-Urnm" if args.local_dns else "-Urn", "bash", str(script), str(binaries[mode]), mode, scenario,
                           "--cli", "--workers", "2", "--seconds", str(args.seconds), "--rate", str(args.rate),
                           "--burst", "8", "--inflight", "48", "--proxy-cpus", args.proxy_cpus,
                           "--harness-cpus", args.harness_cpus, "--singbox-cpus", args.singbox_cpus,
                           "--rule-count", str(args.rule_count)]
                if args.logical_rules:
                    command.append("--logical-rules")
                env = os.environ.copy()
                if args.local_dns:
                    env["NEXUS_BENCH_LOCAL"] = "1"
                result = subprocess.run(command, text=True, capture_output=True, env=env)
                try:
                    sample = json.loads(result.stdout.strip())
                except (ValueError, json.JSONDecodeError):
                    sample = {"aborted": "invalid benchmark output", "stdout": result.stdout[-16000:]}
                sample.update(record="sample", round=round_index + 1, requested_mode=mode,
                              requested_scenario=scenario, exit_code=result.returncode)
                if result.returncode:
                    failures += 1
                    sample["stderr"] = result.stderr[-16000:]
                output.write(json.dumps(sample, sort_keys=True) + "\n")
                output.flush()
                print(f"round {round_index + 1} {scenario} {mode}: exit {result.returncode}", flush=True)
sys.exit(bool(failures))
