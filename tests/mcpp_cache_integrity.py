#!/usr/bin/env python3
"""Exercise installed-package audit failures in a disposable cache copy."""

import argparse
import json
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / ".mcpp/.xlings/data/runtimedir")
    parser.add_argument("--installed", type=Path, default=ROOT / ".mcpp/.xlings/data/xpkgs")
    args = parser.parse_args()
    pin = json.loads((ROOT / "3rdparty/mcpp-pins.json").read_text())["proxy"]
    relative = Path("nexus-x-ngcpp-proxy") / pin["version"]
    with tempfile.TemporaryDirectory(prefix="nexus-mcpp-cache-test-") as tmp:
        installed = Path(tmp) / "xpkgs"
        base = installed / relative
        base.parent.mkdir(parents=True)
        shutil.copytree(args.installed / relative, base, symlinks=True)
        command = [sys.executable, str(ROOT / "scripts/mcpp-verify-installed.py"),
                   "--cache", str(args.cache), "--installed", str(installed), "proxy"]

        def check(expected: str | None = None) -> None:
            result = subprocess.run(command, capture_output=True, text=True)
            if expected is None and result.returncode != 0:
                raise RuntimeError(result.stderr)
            if expected is not None and (result.returncode == 0 or expected not in result.stderr):
                raise RuntimeError(f"expected {expected!r}: {result.returncode}\n{result.stderr}")

        check()
        source = base / pin["source_root"] / "include/proxy/v4/proxy.h"
        data = source.read_bytes()
        source.write_bytes(data + b"\n")
        check("file differs from verified archive")
        source.write_bytes(data)
        extra = source.parent / "unexpected.hpp"
        extra.write_text("extra\n")
        check("extra")
        extra.unlink()
        mode = stat.S_IMODE(source.stat().st_mode)
        source.chmod(mode ^ stat.S_IXUSR)
        check("mode differs from archive")
        source.chmod(mode)
        link = base / pin["source_root"] / "docs/README.md"
        target = link.readlink()
        link.unlink()
        link.symlink_to("../incorrect.md")
        check("symlink differs from archive")
        link.unlink()
        link.symlink_to(target)
        generated = base / "mcpp_generated/proxy.cppm"
        data = generated.read_bytes()
        generated.write_bytes(data + b"\n")
        check("generated file differs from descriptor")
        generated.write_bytes(data)
        descriptor = base / ".xpkg.lua"
        data = descriptor.read_bytes()
        descriptor.write_bytes(data + b"\n")
        check("installed descriptor differs")
        descriptor.write_bytes(data)
        check()
    print("installed cache audit rejects changed source, extra file, mode, symlink, generated file and descriptor")


if __name__ == "__main__":
    main()
