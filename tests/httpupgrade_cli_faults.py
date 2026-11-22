#!/usr/bin/env python3
"""Run the ordinary-ID1 XUDP and pre-VLESS candidate matrix on one saved CLI."""
import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import shlex
import subprocess
import sys
import time


def commands(binary, scripts):
    result = []
    for workers in (1, 2):
        for ipv6 in (False, True):
            for error in ("length", "oversized", "kind", "options", "address", "truncated-meta", "truncated-payload"):
                result.append([sys.executable, scripts / "xudp_socks_faults.py", binary, "--httpupgrade", "--workers", str(workers), "--error", error]
                              + (["--ipv6"] if ipv6 else []))
        for mode in ("retry", "blocked"):
            for failure in ("status", "framing", "alpn"):
                result.append([sys.executable, scripts / "vless_candidate_retry.py", binary, mode, "--httpupgrade", "--workers", str(workers), "--failure", failure])
        result.append([sys.executable, scripts / "vless_candidate_retry.py", binary, "stop", "--httpupgrade", "--workers", str(workers)])
    result.extend([[sys.executable, scripts / "xudp_socks_faults.py", binary],
                   [sys.executable, scripts / "xudp_socks_faults.py", binary, "--ipv6"]])
    return [[str(value) for value in command] for command in result]


def run(command):
    started = time.monotonic()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        checked = {"command": command, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    except subprocess.TimeoutExpired as error:
        checked = {"command": command, "exit_code": 124, "stdout": str(error.stdout), "stderr": str(error.stderr)}
    checked["seconds"] = round(time.monotonic() - started, 3)
    print(("PASS " if not checked["exit_code"] else "FAIL ") + shlex.join([pathlib.Path(command[1]).name, *command[3:]]), flush=True)
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--evidence", type=pathlib.Path)
    parser.add_argument("--list", action="store_true", help="print commands without running programs")
    args = parser.parse_args()
    binary, scripts = args.binary.resolve(), pathlib.Path(__file__).resolve().parent
    selected = commands(binary, scripts)
    if args.list:
        for command in selected:
            print(shlex.join(command))
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(run, selected))
    if args.evidence:
        sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        args.evidence.write_text(json.dumps({"binary_sha256": sha(binary),
            "driver_sha256": {name: sha(scripts / name) for name in ("xudp_socks_faults.py", "vless_candidate_retry.py")},
            "results": results}, indent=2) + "\n")
    failed = [result for result in results if result["exit_code"]]
    print(f"HTTPUpgrade ordinary-ID1/candidate matrix: {len(results) - len(failed)}/{len(results)} passed", flush=True)
    for result in failed:
        print(json.dumps(result), flush=True)
    raise SystemExit(bool(failed))


if __name__ == "__main__":
    main()
