#!/usr/bin/env python3
"""Compare installed mcpp source packages with verified archives and descriptors.

This is an explicit offline audit, not an automatic check on every build. It
compares archived files, modes, symlinks and generated files and rejects extra
entries. For patched variants it audits the source tree against the archive plus
the locked patch; inherited installation metadata and generated files are not
audited, and mcpp-normalized directory modes are not compared. It never modifies
the cache.
"""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
VERIFY = runpy.run_path(str(ROOT / "tests/mcpp_pinned_deps.py"))
PINS = VERIFY["PINS"]


def cache_paths(root: Path) -> set[str]:
    paths = set()
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            paths.add((Path(current) / name).relative_to(root).as_posix())
    return paths


def compare_archive(archive: Path, base: Path, root_name: str,
                    patched: dict[str, bytes] | None = None,
                    additions: set[str] | None = None) -> None:
    root = base / root_name
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"{root}: source root is absent or a symlink")
    expected_paths = set()
    with tarfile.open(archive, "r|*") as tar:
        for member in tar:
            parts = PurePosixPath(member.name).parts
            if not parts or parts[0] != root_name or ".." in parts:
                raise ValueError(f"{archive}: unexpected member {member.name!r}")
            relative = PurePosixPath(*parts[1:])
            if not relative.parts:
                continue
            key = relative.as_posix()
            if key in expected_paths:
                raise ValueError(f"{archive}: duplicate member {member.name!r}")
            expected_paths.add(key)
            target = root.joinpath(*relative.parts)
            if member.issym():
                if not target.is_symlink() or os.readlink(target) != member.linkname:
                    raise ValueError(f"{target}: symlink differs from archive")
                continue
            if target.is_symlink() or not target.resolve().is_relative_to(root.resolve()):
                raise ValueError(f"{target}: unexpected symlink or path outside source root")
            if member.isdir():
                if not target.is_dir():
                    raise ValueError(f"{target}: expected directory")
            elif member.isfile():
                if not target.is_file():
                    raise ValueError(f"{target}: expected file")
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError(f"{archive}: cannot read {member.name}")
                with source, target.open("rb") as installed:
                    expected = (hashlib.sha256(patched[key]).digest() if patched is not None and key in patched
                                else hashlib.file_digest(source, "sha256").digest())
                    if expected != hashlib.file_digest(installed, "sha256").digest():
                        raise ValueError(f"{target}: file differs from verified archive")
            else:
                raise ValueError(f"{archive}: unsupported member type for {member.name}")
            # mcpp copies variant directories with its own directory mode.
            if not (patched is not None and member.isdir()) and stat.S_IMODE(target.stat().st_mode) != member.mode & 0o7777:
                raise ValueError(f"{target}: mode differs from archive")
    for key in additions or ():
        relative = PurePosixPath(key)
        if key in expected_paths or any(parent.as_posix() not in expected_paths
                                        for parent in relative.parents if parent.parts):
            raise ValueError(f"{root}: unexpected added path or parent: {key}")
        target = root.joinpath(*relative.parts)
        if (target.is_symlink() or not target.resolve().is_relative_to(root.resolve())
                or not target.is_file() or stat.S_IMODE(target.stat().st_mode) != 0o644
                or target.read_bytes() != patched[key]):
            raise ValueError(f"{target}: added file differs from exact patch")
        expected_paths.add(key)
    actual_paths = cache_paths(root)
    if expected_paths != actual_paths:
        missing = sorted(expected_paths - actual_paths)
        extra = sorted(actual_paths - expected_paths)
        raise ValueError(f"{root}: missing {missing[:5]}, extra {extra[:5]}")


def generated_files(name: str, descriptor: bytes) -> dict[str, bytes]:
    if name == "proxy":
        path = "mcpp_generated/proxy.cppm"
        return {path: VERIFY["generated"](descriptor, path, b"[=[", b"]=]")}
    if name in ("nghttp2", "ngtcp2", "nghttp3"):
        path = "mcpp_generated/config.h"
        # Lua drops the first newline after a long-string opening delimiter.
        return {path: VERIFY["generated"](descriptor, path, b"[==[", b"]==]").removeprefix(b"\n")}
    if name == "glaze":
        path = "mcpp_generated/nexus_glaze_kdl_anchor.c"
        literal = b'"int nexus_glaze_kdl_headers_anchor(void) { return 0; }\\n"'
        if descriptor.count(b'["' + path.encode() + b'"] = ' + literal) != 1:
            raise ValueError("Glaze: generated anchor declaration differs")
        return {path: b"int nexus_glaze_kdl_headers_anchor(void) { return 0; }\n"}
    return {}


def patch_paths(patch: Path, root: str) -> list[tuple[PurePosixPath, bool]]:
    """Accept exact unified modifications and additions, never renames or deletes."""
    lines = patch.read_text(encoding="utf-8").splitlines()
    paths = []
    i = 0
    while i < len(lines):
        if not lines[i].startswith("--- ") or i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
            raise ValueError(f"{patch}: unsupported unified patch header")
        old, new = lines[i][4:], lines[i + 1][4:]
        added = old == "/dev/null"
        if not new.startswith("b/") or (not added and (not old.startswith("a/") or old[2:] != new[2:])):
            raise ValueError(f"{patch}: unsupported patch paths")
        raw = new[2:]
        path = PurePosixPath(raw)
        if (path.is_absolute() or len(path.parts) < 2 or path.parts[0] != root
                or ".." in path.parts or any(ch.isspace() for ch in raw)
                or path.as_posix() != raw or path in (p for p, _ in paths)):
            raise ValueError(f"{patch}: unsafe or duplicate patch path")
        paths.append((path, added))
        i += 2
        hunks = 0
        while i < len(lines) and lines[i].startswith("@@ "):
            match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", lines[i])
            if not match:
                raise ValueError(f"{patch}: malformed hunk")
            old_left = int(match.group(2) or 1)
            new_left = int(match.group(4) or 1)
            i += 1
            while old_left or new_left:
                if i >= len(lines) or not lines[i] or lines[i][0] not in " +-":
                    raise ValueError(f"{patch}: malformed hunk contents")
                marker = lines[i][0]
                old_left -= marker != "+"
                new_left -= marker != "-"
                if old_left < 0 or new_left < 0:
                    raise ValueError(f"{patch}: hunk length mismatch")
                i += 1
                if i < len(lines) and lines[i] == r"\ No newline at end of file":
                    i += 1
            hunks += 1
        if not hunks:
            raise ValueError(f"{patch}: no patch hunks")
    if not paths:
        raise ValueError(f"{patch}: empty patch")
    return paths


def patched_files(archive: Path, pin: dict) -> tuple[dict[str, bytes], set[str]]:
    """Apply ordered pinned patches to archive inputs in an isolated scratch tree."""
    patches = [ROOT / entry["path"] for entry in VERIFY["mcpp_patch_entries"](pin)]
    plans = [(patch, patch_paths(patch, pin["source_root"])) for patch in patches]
    touched: set[PurePosixPath] = set()
    additions: set[PurePosixPath] = set()
    with tempfile.TemporaryDirectory(prefix="nexus-mcpp-audit-") as scratch:
        directory = Path(scratch)
        with tarfile.open(archive, "r:*") as tar:
            for patch, paths in plans:
                for path, added in paths:
                    target = directory.joinpath(*path.parts)
                    try:
                        member = tar.getmember(path.as_posix())
                    except KeyError:
                        member = None
                    if added:
                        if member is not None or path in touched:
                            raise ValueError(f"{patch}: added path already exists: {path}")
                        additions.add(path)
                    elif path not in touched:
                        if member is None or not member.isfile():
                            raise ValueError(f"{archive}: patch input is not a file: {path}")
                        source = tar.extractfile(member)
                        if source is None:
                            raise ValueError(f"{archive}: cannot read {path}")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with source:
                            target.write_bytes(source.read())
                    target.parent.mkdir(parents=True, exist_ok=True)
                    touched.add(path)
                result = subprocess.run(["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch)],
                                        cwd=directory, check=True, capture_output=True, text=True,
                                        env={**os.environ, "LC_ALL": "C"})
                if re.search(r"(?m)^Hunk #\d+ succeeded at \d+ \(offset [+-]?\d+ lines?\)\.$", result.stdout):
                    raise ValueError(f"{patch}: hunk applied at an offset")
        return ({PurePosixPath(*path.parts[1:]).as_posix(): directory.joinpath(*path.parts).read_bytes()
                 for path in touched},
                {PurePosixPath(*path.parts[1:]).as_posix() for path in additions})


def variant_path(name: str, pin: dict, variants: Path, lock: dict) -> Path:
    package = Path(pin["descriptor"]).stem
    expected = [f'{patch["path"]}#sha256:{patch["sha256"]}'
                for patch in VERIFY["mcpp_patch_entries"](pin)]
    matches = [(key, entry) for key, entry in lock["package"].items()
               if key.startswith(package + "+p") and entry.get("version") == pin["version"]
               and entry.get("patches") == expected]
    if len(matches) != 1:
        raise ValueError(f"{name}: expected exactly one locked ordered-patch variant")
    key, entry = matches[0]
    digest = entry.get("variant", "")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or key != package + "+p" + digest[:12]:
        raise ValueError(f"{name}: invalid locked variant identity")
    base = variants / package / (pin["version"] + "+p" + digest[:12])
    marker = base / ".mcpp-variant"
    if base.is_symlink() or marker.is_symlink() or not marker.is_file() or marker.read_text().strip() != digest:
        raise ValueError(f"{base}: variant marker differs from lock")
    return base


def verify_package(name: str, cache: Path, installed: Path, variants: Path, lock: dict) -> None:
    pin = PINS[name]
    if name == "ngtcp2":
        VERIFY["verify_ngtcp2_manifest"](ROOT / "src/mcpp.toml", pin)
    archive = VERIFY["checked_archive"](cache, name)
    package = Path(pin["descriptor"]).stem.removeprefix("nexus.")
    base = installed / f"nexus-x-{package}" / pin["version"]
    descriptor = (ROOT / pin["descriptor"]).read_bytes()
    if VERIFY["mcpp_patch_entries"](pin):
        base = variant_path(name, pin, variants, lock)
        patched, additions = patched_files(archive, pin)
        compare_archive(archive, base, pin["source_root"], patched, additions)
        print(f"{name}: locked variant source matches verified archive and exact ordered patches; inherited installation metadata and generated files not audited")
        return
    installed_descriptor = base / ".xpkg.lua"
    if (installed_descriptor.is_symlink() or not installed_descriptor.is_file()
            or installed_descriptor.read_bytes() != descriptor):
        raise ValueError(f"{base}: installed descriptor differs")
    compare_archive(archive, base, pin["source_root"])
    expected = generated_files(name, descriptor)
    generated_root = base / "mcpp_generated"
    if expected:
        if generated_root.is_symlink() or not generated_root.is_dir():
            raise ValueError(f"{generated_root}: missing or is a symlink")
        expected_names = set()
        for path in expected:
            relative = PurePosixPath(path).relative_to("mcpp_generated")
            expected_names.add(relative.as_posix())
            expected_names.update(parent.as_posix() for parent in relative.parents if parent.parts)
        actual_names = cache_paths(generated_root)
        if actual_names != expected_names:
            raise ValueError(f"{generated_root}: unexpected or missing generated files")
        for path, data in expected.items():
            target = base / path
            if (target.is_symlink() or not target.resolve().is_relative_to(generated_root.resolve())
                    or target.read_bytes() != data):
                raise ValueError(f"{target}: generated file differs from descriptor")
    elif generated_root.exists() or generated_root.is_symlink():
        raise ValueError(f"{generated_root}: unexpected generated directory")
    print(f"{name}: archive, installed source, descriptor and generated files match")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / ".mcpp/.xlings/data/runtimedir")
    parser.add_argument("--installed", type=Path, default=ROOT / ".mcpp/.xlings/data/xpkgs")
    parser.add_argument("--variants", type=Path, default=Path.home() / ".mcpp/cache/src")
    parser.add_argument("--lock", type=Path, default=ROOT / "mcpp.lock")
    parser.add_argument("packages", nargs="*", choices=list(PINS), help="default: all pinned packages")
    args = parser.parse_args()
    with args.lock.open("rb") as source:
        lock = tomllib.load(source)
    for name in args.packages or PINS:
        verify_package(name, args.cache, args.installed, args.variants, lock)


if __name__ == "__main__":
    main()
