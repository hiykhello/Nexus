#!/usr/bin/env python3
"""Check module-interface rebuilds across two mcpp packages.

The temporary projects have separate build directories.  Build the library on
its own before rebuilding its consumer, as happens when working on a subset of
the project.  The object checks supplement running the resulting executable:
the executable alone might happen to work even with a stale consumer.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


MANIFEST_HEADER = '''[package]
name = "{name}"
version = "0.1.0"
standard = "c++26"
mcpp = ">=2026.11.21.1"

[toolchain]
default = "llvm@23.1.6"

[target.x86_64-linux-gnu]
sysroot = "glibc@system"
'''


def run(cwd: Path, command: list[str], env: dict[str, str]) -> None:
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"{command!r} failed in {cwd}:\n{result.stdout}")


def result(cwd: Path) -> dict:
    last = json.loads((cwd / "target/.last-result.json").read_text())
    if last.get("kind") != "mcpp.last-result" or last["data"]["status"] != "ok":
        raise RuntimeError("mcpp did not record a successful build")
    record = json.loads(Path(last["data"]["result"]).read_text())
    if record.get("kind") != "mcpp.result" or record["data"]["status"] != "ok":
        raise RuntimeError("mcpp build result is not successful")
    return record["data"]


def objects(build: Path, sources: list[Path]) -> dict[Path, Path]:
    rows = json.loads((build / "compile_commands.json").read_text())
    found: dict[Path, Path] = {}
    wanted = {source.resolve() for source in sources}
    for row in rows:
        directory = Path(row["directory"])
        source = Path(row["file"])
        source = (directory / source).resolve()
        if source not in wanted:
            continue
        if source in found:
            raise RuntimeError(f"multiple compile commands for {source}")
        output = Path(row["output"])
        output = (directory / output).resolve()
        if not output.is_file():
            raise RuntimeError(f"missing compiled object {output}")
        found[source] = output
    if found.keys() != wanted:
        raise RuntimeError(f"missing compile commands: {wanted - found.keys()}")
    return found


def stamps(paths: dict[Path, Path]) -> dict[Path, int]:
    return {source: output.stat().st_mtime_ns for source, output in paths.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, help="initialized mcpp home (default: mcpp's configured home)")
    args = parser.parse_args()
    env = {**os.environ, "MCPP_VERIFY_MODGRAPH": "1", "MCPP_JOBS": "1"}
    command = ["mcpp", "--offline"]
    if args.home:
        command += ["--home", str(args.home.resolve())]
    command += ["build", "--cache", "local", "--target", "x86_64-linux-gnu", "-j", "1", "--strict"]

    with tempfile.TemporaryDirectory(prefix="nexus-mcpp-module-incremental-") as temporary:
        root = Path(temporary)
        library, consumer = root / "library", root / "consumer"
        library.mkdir()
        consumer.mkdir()
        (library / "mcpp.toml").write_text(MANIFEST_HEADER.format(name="incremental-model") + '''
[build]
sources = ["layout.cppm", "model.cppm", "model.cpp"]

[targets.model]
kind = "lib"
''')
        (consumer / "mcpp.toml").write_text(MANIFEST_HEADER.format(name="incremental-client") + '''
[dependencies]
incremental-model = { path = "../library" }

[build]
sources = []

[targets.client]
kind = "bin"
main = "client.cpp"
''')
        interface, layout = library / "model.cppm", library / "layout.cppm"
        implementation, client = library / "model.cpp", consumer / "client.cpp"
        interface.write_text(
            "export module model;\nimport std;\nexport import model.layout;\n"
            "export inline constexpr int expected = 42;\nexport auto value() -> Value;\n"
        )
        layout.write_text("export module model.layout;\nexport struct Value { int a; };\n")
        implementation.write_text("module model;\nauto value() -> Value { return {42}; }\n")
        client.write_text("import std;\nimport model;\nauto main() -> int { return value().a == expected ? 0 : 1; }\n")

        def build_consumer() -> tuple[dict[Path, Path], Path]:
            run(consumer, command, env)
            data = result(consumer)
            build = Path(data["configuration"]["outputDir"])
            candidates = [Path(item["path"]) for item in data["artifacts"]
                          if item["name"] == "client" and item["kind"] == "bin"]
            if len(candidates) != 1 or not candidates[0].is_file():
                raise RuntimeError("expected one built client")
            run(consumer, [str(candidates[0])], env)
            return objects(build, [layout, interface, implementation, client]), candidates[0]

        def changed(previous: dict[Path, int], current: dict[Path, Path], *sources: Path) -> None:
            now = stamps(current)
            for source in sources:
                source = source.resolve()
                if now[source] <= previous[source]:
                    raise RuntimeError(f"consumer graph did not rebuild {source}")

        run(library, command, env)
        paths, binary = build_consumer()
        before = stamps(paths)
        interface.write_text(
            "export module model;\nimport std;\nexport import model.layout;\n"
            "export inline constexpr int expected = 43;\nexport auto value() -> Value;\n"
        )
        implementation.write_text("module model;\nauto value() -> Value { return {43}; }\n")
        run(library, command, env)
        paths, binary = build_consumer()
        changed(before, paths, interface, implementation, client)

        before = stamps(paths)
        layout.write_text("export module model.layout;\nexport struct Value { int padding; int a; };\n")
        implementation.write_text("module model;\nauto value() -> Value { return {7, 43}; }\n")
        run(library, command, env)
        paths, binary = build_consumer()
        changed(before, paths, layout, implementation, client)

        before = stamps(paths)
        layout.write_text("export module model.layout;\nexport struct Value { int a; };\n")
        implementation.write_text("module model;\nauto value() -> Value { return {43}; }\n")
        run(library, command, env)
        paths, binary = build_consumer()
        changed(before, paths, layout, implementation, client)
        before, binary_stamp = stamps(paths), binary.stat().st_mtime_ns
        paths, binary = build_consumer()
        if stamps(paths) != before or binary.stat().st_mtime_ns != binary_stamp:
            raise RuntimeError("unchanged consumer graph rebuilt")
    print("mcpp module-interface incremental rebuilds passed")


if __name__ == "__main__":
    main()
