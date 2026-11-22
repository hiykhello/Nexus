#!/usr/bin/env python3
"""Relink an existing HTTP3 owner test with calibrated native rcbuf counters."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from quic_tls_relink import command_prefix, expand_response


SYMBOLS = ("nghttp3_rcbuf_incref", "nghttp3_rcbuf_decref")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--build-dir", type=Path)
    source.add_argument("--link-command", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.build_dir:
        if not args.target:
            parser.error("--build-dir requires --target")
        directory = args.build_dir.resolve()
        result = subprocess.run(["ninja", "-C", str(directory), "-t", "compdb", "-x", "cxx_link"],
                                check=True, text=True, capture_output=True)
        entries = [entry for entry in json.loads(result.stdout) if entry["output"] == args.target]
        if len(entries) != 1:
            raise RuntimeError("expected exactly one existing HTTP3 owner link target")
        entry = entries[0]
        directory = Path(entry["directory"]).resolve()
        arguments = command_prefix(entry["command"])
        artifact = directory / args.target
    else:
        entry = json.loads(args.link_command.read_text())
        directory = Path(entry["directory"]).resolve()
        arguments = entry["arguments"]
        artifact = None
    arguments = expand_response(arguments, directory)
    wrappers = {"-Wl,--wrap=" + symbol for symbol in SYMBOLS}
    arguments = [argument for argument in arguments if argument not in wrappers]
    if "-c" in arguments or arguments.count("-o") != 1:
        raise RuntimeError("expected an executable link command")
    position = arguments.index("-o") + 1
    artifact = artifact or directory / arguments[position]
    symbols = subprocess.run(["nm", "--defined-only", "--format=posix", str(artifact)],
                             check=True, text=True, capture_output=True).stdout
    defined = {line.split()[0] for line in symbols.splitlines() if line.split()}
    if not all(symbol in defined and "__wrap_" + symbol in defined for symbol in SYMBOLS):
        raise RuntimeError("exact native rcbuf functions and test counters are required")
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="nexus-http3-refs-")) / "http3-owner"
    if output == artifact.resolve() or output.exists():
        raise RuntimeError("output must be a new path distinct from the source artifact")
    arguments[position] = str(output)
    arguments += sorted(wrappers)
    subprocess.run(arguments, cwd=directory, check=True, timeout=120)
    result = subprocess.run([str(output), "--wrapped-refs"], text=True, capture_output=True, timeout=60)
    report = {"directory": str(directory), "arguments": arguments, "source": str(artifact),
              "source_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
              "output": str(output), "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
              "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(result.stdout, end="")
    if result.returncode:
        raise RuntimeError(f"calibrated reference-count test failed: {result.returncode} {result.stderr}")


if __name__ == "__main__":
    main()
