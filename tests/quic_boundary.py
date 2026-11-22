#!/usr/bin/env python3
"""Compare generated QUIC C ABI layouts with the pinned native headers.

Each probe is a separate translation unit. Native headers and named-module
types are never mixed in a consumer. The actual modules and C symbol calls
are tested by the mcpp graph and HTTP/3/QUIC consumers separately.
"""

import argparse
import difflib
from pathlib import Path
import re
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = runpy.run_path(str(ROOT / "scripts/mcpp-quic-modules.py"))


def fields(body: str) -> list[tuple[str, list[str]]]:
    structs = []
    pattern = r"typedef (?:struct|union) (?:__attribute__\(\(aligned\(\d+\)\)\) )?(\w+) \{([^{}]*)\} (\w+);"
    for match in re.finditer(pattern, body):
        tag, members, name = match.groups()
        if name != tag:
            raise ValueError(f"unsupported ABI tag alias {tag}/{name}")
        names = []
        for declaration in members.split(";"):
            declaration = declaration.strip()
            if not declaration:
                continue
            field = re.search(r"\b(\w+)\s*(?:\[[^\]]+\])?\s*$", declaration)
            if not field:
                raise ValueError(f"unsupported ABI field: {declaration}")
            names.append(field[1])
        structs.append((name, names))
    if not structs:
        raise ValueError("no ABI structs were checked")
    return structs


def probe(body: str, structs: list[tuple[str, list[str]]], name: str, native: bool) -> str:
    lines = []
    if not native:
        body = re.sub(r"^export module [^;]+;\n|^import std;\n", "", body, flags=re.M)
        lines.append(body.replace("export namespace", "namespace"))
        lines.append(f"using namespace nexus_{name}_abi;")
    lines.append("int main() {")
    for tag, members in structs:
        lines.append(f'std::printf("{tag} %zu %zu\\n",sizeof({tag}),alignof({tag}));')
        for member in members:
            lines.append(f'std::printf("{tag}.{member} %zu %zu\\n",'
                         f'__builtin_offsetof({tag},{member}),sizeof((({tag}*)0)->{member}));')
    lines.append("}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", choices=("ngtcp2", "nghttp3"))
    parser.add_argument("archive", type=Path)
    parser.add_argument("source", type=Path, help="native extracted release root")
    parser.add_argument("--compiler", default="/usr/bin/g++")
    args = parser.parse_args()
    outputs = GENERATOR["modules"](args.name, args.archive, args.compiler)
    for path, expected in outputs.items():
        if path.read_text() != expected:
            raise ValueError(f"{path}: generated module differs from upstream declarations")
    abi = outputs[ROOT / f"3rdparty/modules/{args.name}.cppm"]
    structs = fields(abi)
    with tempfile.TemporaryDirectory(prefix="nexus-quic-abi-") as directory:
        directory = Path(directory)
        results = []
        for native in (True, False):
            source = directory / ("native.cpp" if native else "generated.cpp")
            binary = source.with_suffix("")
            source.write_text(probe(abi, structs, args.name, native))
            command = [args.compiler, "-std=c++26", "-Werror", "-include", "bits/stdc++.h"]
            if native:
                command += ["-I", str(args.source / "lib/includes"), "-include", f"{args.name}/{args.name}.h"]
            subprocess.run(command + [str(source), "-o", str(binary)], check=True, capture_output=True, text=True)
            results.append(subprocess.run([str(binary)], check=True, capture_output=True, text=True).stdout)
        if results[0] != results[1]:
            diff = "".join(difflib.unified_diff(results[0].splitlines(True), results[1].splitlines(True),
                                                fromfile="native", tofile="generated"))
            raise ValueError(f"{args.name}: native/generated ABI mismatch\n{diff}")
    count = sum(len(members) for _, members in structs)
    print(f"{args.name}: exact generated declarations, {len(structs)} struct/union sizes/alignments "
          f"and {count} field offsets/sizes match the pinned native header")


if __name__ == "__main__":
    main()
