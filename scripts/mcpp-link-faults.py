#!/usr/bin/env python3
"""Build and run socket fault tests with the matching linker wrappers."""

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
TUN_GROUPS = {
    "udp-receive": (
        {"recvfrom"},
        {"udp-deferred-allocation", "udp-output-allocation", "udp-reply-allocation",
         "udp-direct-fault", "udp-engine-fault"},
    ),
    "udp-send": ({"sendto"}, {"udp-send-fault", "transport-udp-send-fault"}),
    "tcp-receive": ({"recv"}, {"tcp-direct-allocation"}),
    "tcp-socket": ({"socket"}, {"tcp-stack-allocation"}),
    "tcp-timeout": ({"poll", "socket", "close"}, {"tcp-direct-timeout"}),
    "socket-mark": ({"setsockopt", "connect", "sendto"}, {"direct-socket-mark-failure"}),
}
UDP_GROUPS = {
    "send": ({"sendto"}, {"socks-udp-direct", "uot-direct"}),
    "ingress": ({"sendto", "recvfrom"}, {"socks-udp-ingress"}),
    "ss-relay": ({"socket", "setsockopt", "sendto", "recvfrom"}, {"ss-udp-relay-fault"}),
}
SUITES = {"tun": ("tun-fault-tests", TUN_GROUPS), "udp": ("udp-fault-tests", UDP_GROUPS)}


def run_artifact(artifact: dict) -> None:
    # mcpp records the runner, working directory and loader environment. Older
    # build records only have path; preserve their native launch convention.
    launch = artifact.get("launch")
    argv = launch["argv"] if launch else [artifact["path"]]
    cwd = launch["cwd"] if launch else ROOT
    env = os.environ.copy()
    if launch:
        env.update(launch["env"])
    subprocess.run(argv, cwd=cwd, env=env, check=True, timeout=60)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=SUITES, action="append", help="run only this suite; may be repeated")
    parser.add_argument("--group", action="append", help="run only this group; may be repeated")
    parser.add_argument("--home", help="mcpp home")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--target", default="x86_64-linux-gnu")
    parser.add_argument("--mcpp", default="mcpp")
    args = parser.parse_args()

    env = os.environ.copy()
    env["MCPP_VERIFY_MODGRAPH"] = "1"
    suites = args.suite or SUITES
    available = {group for suite in suites for group in SUITES[suite][1]}
    unknown = set(args.group or []) - available
    if unknown:
        parser.error(f"groups not in the selected suites: {', '.join(sorted(unknown))}")
    for suite, group in ((suite, group) for suite in suites for group in SUITES[suite][1]
                         if not args.group or group in args.group):
        member, groups = SUITES[suite]
        wrappers, expected = groups[group]
        cmd = [args.mcpp, "--locked"]
        if args.offline:
            cmd.append("--offline")
        if args.home:
            cmd.extend(["--home", args.home])
        cmd.extend(["build", "-p", f"nexus.{member}", "--features", group,
                    "--profile", group, "--target", args.target, "--strict", "-j", "1",
                    "--message-format", "json"])
        print(f"Building {suite}/{group}", flush=True)
        result = subprocess.run(cmd, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE)
        if result.returncode:
            print(result.stdout, file=sys.stderr)
            return result.returncode
        report = None
        for line in result.stdout.splitlines():
            if not line.startswith("{"):
                continue
            event = json.loads(line)
            if event.get("kind") == "mcpp.build":
                report = event["data"]
        if not report or report.get("status") != "ok":
            raise RuntimeError(f"{group}: mcpp did not report a successful build")
        artifacts = {a["name"]: a for a in report["artifacts"] if a["kind"] == "bin"}
        if set(artifacts) != expected:
            raise RuntimeError(f"{group}: expected {sorted(expected)}, got {sorted(artifacts)}")
        build_dir = Path(report["configuration"]["outputDir"])
        for name in sorted(expected):
            goal = f"bin/{member}/{name}"
            query = subprocess.run(["ninja", "-C", str(build_dir), "-t", "commands", goal],
                                   cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE)
            link = query.stdout.splitlines()[-1]
            prefix = "-Wl,--wrap="
            actual = {word.removeprefix(prefix) for word in shlex.split(link) if word.startswith(prefix)}
            if actual != wrappers:
                raise RuntimeError(f"{name}: expected wrappers {sorted(wrappers)}, got {sorted(actual)}")
            print(f"Running {name}", flush=True)
            run_artifact(artifacts[name])
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
