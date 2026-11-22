#!/usr/bin/env python3
"""Exercise the generated mcpp snapshot guard in an isolated profile tree."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, help="initialized mcpp home (defaults to mcpp's selected home)")
    parser.add_argument("--cache", type=Path, default=ROOT / ".mcpp/.xlings/data/runtimedir",
                        help="directory containing all pinned source archives")
    args = parser.parse_args()
    generator = ROOT / "scripts/mcpp-generate-pinned-guard.py"
    inputs = runpy.run_path(str(generator))["INPUTS"]

    with tempfile.TemporaryDirectory(prefix="nexus-mcpp-guard-test-") as temporary:
        tree = Path(temporary)
        for name in [*inputs, "src/build/mcpp_pinned_guard.cpp"]:
            destination = tree / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)

        profile = tree / "mcpp/profile"
        profile.mkdir(parents=True)
        for name in ("src", "tests", "3rdparty", "scripts"):
            (profile / name).symlink_to(f"../../{name}", target_is_directory=True)
        (tree / "src/main.cpp").write_text("int main() { return 0; }\n")
        (profile / "mcpp.toml").write_text('''[package]
name = "nexus-pinned-guard-test"
version = "0.1.0"
standard = "c++26"
mcpp = ">=2026.11.21.1"
[toolchain]
default = "llvm@23.1.3"
[target.x86_64-linux-gnu]
sysroot = "glibc@system"
[build]
sources = ["src/build/mcpp_pinned_guard.cpp"]
[targets.probe]
kind = "bin"
main = "src/main.cpp"
''')
        verifier = [sys.executable, str(tree / "scripts/mcpp-generate-pinned-guard.py"),
                    "--check", "--cache", str(args.cache.resolve())]
        subprocess.run(verifier, check=True, capture_output=True, text=True)

        command = ["mcpp", "--offline"]
        if args.home:
            command += ["--home", str(args.home.resolve())]
        command += ["build", "--target", "x86_64-linux-gnu", "-j", "1", "--strict"]
        env = os.environ.copy()
        env["MCPP_VERIFY_MODGRAPH"] = "1"

        def build(expect_success: bool, changed: bool | None = None) -> str:
            result = subprocess.run(command, cwd=profile, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
            if (result.returncode == 0) != expect_success:
                raise RuntimeError(f"unexpected build result {result.returncode}:\n{result.stdout}")
            if changed is not None and ("Compiling " in result.stdout) != changed:
                raise RuntimeError(f"unexpected incremental work:\n{result.stdout}")
            return result.stdout

        build(True, True)
        command.insert(2, "--locked")
        build(True, False)
        patch = tree / "3rdparty/patches/capy/cpo_modules.patch"
        original = patch.read_bytes()
        patch.write_bytes(original + b"\n")
        output = build(False)
        if "cpo_modules.patch changed" not in output:
            raise RuntimeError(f"the changed patch failed for another reason:\n{output}")
        # This edit also makes the pinned archive and generated snapshot differ;
        # the generator must refuse to bless it rather than updating the guard.
        # Appending whitespace does not change the patch semantics, so alter a
        # real hunk in a separate generator check.
        altered = original.replace(b"--- a/", b"--- missing/", 1)
        if altered == original:
            raise RuntimeError("the test patch has no expected hunk header")
        patch.write_bytes(altered)
        result = subprocess.run(verifier, capture_output=True, text=True)
        if result.returncode == 0:
            raise RuntimeError("the generator accepted an unverified patch")
        patch.write_bytes(original)
        descriptor = tree / "3rdparty/mcpp-index/pkgs/n/nexus.blake3-source.lua"
        original_descriptor = descriptor.read_bytes()
        descriptor.write_bytes(original_descriptor.replace(b'"*/c/blake3.c"', b'"*/c/incorrect.c"', 1))
        if descriptor.read_bytes() == original_descriptor:
            raise RuntimeError("the BLAKE3 descriptor did not contain its expected source")
        output = build(False)
        if "nexus.blake3-source.lua changed" not in output:
            raise RuntimeError(f"the changed descriptor failed for another reason:\n{output}")
        if subprocess.run(verifier, capture_output=True, text=True).returncode == 0:
            raise RuntimeError("the generator accepted an incorrect portable source list")
        descriptor.write_bytes(original_descriptor)
        subprocess.run(verifier, check=True, capture_output=True, text=True)
        build(True, True)
        build(True, False)
    print("mcpp pinned guard: verified inputs, changed patch and source list, recovery and no-op builds passed")


if __name__ == "__main__":
    main()
