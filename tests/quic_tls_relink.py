#!/usr/bin/env python3
"""Relink an existing QUIC TLS test with a calibrated TCP RecordLayer wrapper.

Uses existing objects only. --build-dir/--target read Ninja's expanded link
command without building. --link-command accepts JSON {directory, arguments}
or a single shell command in --directory. The source artifact is left intact.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile


SYMBOL = ("_ZN5nexus3tlsW5nexusW3tlsW6record11RecordLayer6createENS0_S3_15RecordDirection"
          "ENS_6cryptoS1_W6crypto4AeadESt4spanIKhLm18446744073709551615EESB_m")


def command_prefix(command):
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    arguments = list(lexer)
    for index, argument in enumerate(arguments):
        if argument in ("&&", ";", "|", "||", "&"):
            if argument != "&&" or arguments[index + 1:index + 3] != ["mv", "-f"]:
                raise RuntimeError("unsupported shell command in link recipe")
            arguments = arguments[:index]
            break
    return arguments


def expand_response(arguments, directory, depth=0):
    if depth > 8:
        raise RuntimeError("recursive response files in link recipe")
    output = []
    for argument in arguments:
        if argument.startswith("@"):
            path = directory / argument[1:]
            output += expand_response(shlex.split(path.read_text()), directory, depth + 1)
        else:
            output.append(argument)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--build-dir", type=Path)
    source.add_argument("--link-command", type=Path)
    parser.add_argument("--target", help="Ninja bin/... target")
    parser.add_argument("--directory", type=Path, default=Path.cwd())
    parser.add_argument("--source-bin", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.build_dir:
        if not args.target:
            parser.error("--build-dir requires --target")
        directory = args.build_dir.resolve()
        result = subprocess.run(["ninja", "-C", str(directory), "-t", "compdb", "-x", "cxx_link"],
                                check=True, text=True, capture_output=True)
        entries = [item for item in json.loads(result.stdout) if item["output"] == args.target]
        if len(entries) != 1:
            raise RuntimeError("expected exactly one existing Ninja link target")
        entry = entries[0]
        directory = Path(entry["directory"]).resolve()
        arguments = command_prefix(entry["command"])
        artifact = directory / args.target
    else:
        content = args.link_command.read_text()
        if content.lstrip().startswith("{"):
            entry = json.loads(content)
            directory = Path(entry["directory"]).resolve()
            arguments = entry["arguments"]
        else:
            directory = args.directory.resolve()
            arguments = command_prefix(content)
        artifact = None
    arguments = expand_response(arguments, directory)
    wrapper = "-Wl,--wrap=" + SYMBOL
    arguments = [argument for argument in arguments if argument != wrapper]
    if "-c" in arguments or arguments.count("-o") != 1:
        raise RuntimeError("expected a single executable link command")
    output_index = arguments.index("-o") + 1
    artifact = args.source_bin.resolve() if args.source_bin else artifact or directory / arguments[output_index]
    symbols = subprocess.run(["nm", "--defined-only", "--format=posix", str(artifact)],
                             check=True, text=True, capture_output=True).stdout
    defined = {line.split()[0] for line in symbols.splitlines() if line.split()}
    if SYMBOL not in defined or "__wrap_" + SYMBOL not in defined:
        raise RuntimeError("exact RecordLayer factory and test wrapper symbols are required")
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="nexus-quic-tls-wrap-")) / "quic-tls"
    if output == artifact.resolve() or output.exists():
        raise RuntimeError("output must be a new path distinct from the source artifact")
    arguments[output_index] = str(output)
    arguments.append(wrapper)
    subprocess.run(arguments, cwd=directory, check=True, timeout=120)
    report = {"source": str(artifact), "source_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
              "output": str(output), "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
              "directory": str(directory), "arguments": arguments, "symbol": SYMBOL}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(output)


if __name__ == "__main__":
    main()
