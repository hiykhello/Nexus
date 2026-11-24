#!/usr/bin/env python3
"""Check Nexus mcpp pins, generated interfaces and source lists offline.

The caller supplies the pinned archives. Nothing is downloaded and this does
not inspect the already-installed mcpp package cache.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import runpy
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PINS = json.loads((ROOT / "3rdparty/mcpp-pins.json").read_text(encoding="utf-8"))
CACHE = ROOT / ".mcpp/.xlings/data/runtimedir"
HEADERS = {
    "capy": [
        "boost/capy/buffers.hpp", "boost/capy/buffers/buffer_copy.hpp",
        "boost/capy/buffers/buffers_front.hpp",
    ],
    "corosio": [
        "boost/corosio/detail/thread_local_ptr.hpp",
        "boost/corosio/native/detail/uring/uring_types.hpp",
    ],
}


def check_digest(path: Path, expected: str) -> None:
    with path.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected:
        raise ValueError(f"{path}: SHA-256 is {actual}, expected {expected}")


def mcpp_patch_entries(pin: dict) -> list[dict]:
    if "mcpp_patch" in pin and "mcpp_patches" in pin:
        raise ValueError("a pin cannot specify both mcpp_patch and mcpp_patches")
    if "mcpp_patch" in pin:
        return [pin["mcpp_patch"]]
    patches = pin.get("mcpp_patches", [])
    if not isinstance(patches, list) or ("mcpp_patches" in pin and not patches):
        raise ValueError("mcpp_patches must be a nonempty ordered list")
    return patches


def verify_ngtcp2_manifest(manifest: Path, pin: dict) -> None:
    """Require the production build to select the exact pinned patch sequence."""
    with manifest.open("rb") as source:
        config = tomllib.load(source)
    try:
        dependencies = config["feature-deps"]["quic-native"]
        if not isinstance(dependencies, dict) or not isinstance(dependencies.get("nexus", {}), dict):
            raise ValueError("ngtcp2: invalid production dependency table")
        nested = dependencies.get("nexus", {}).get("ngtcp2-source")
        direct = dependencies.get("nexus.ngtcp2-source")
        if nested is not None and direct is not None:
            raise ValueError("ngtcp2: duplicate production dependency")
        dependency = nested if nested is not None else direct
    except (KeyError, TypeError) as error:
        raise ValueError("ngtcp2: missing production dependency") from error
    expected = []
    for patch in mcpp_patch_entries(pin):
        raw = patch["path"]
        path = PurePosixPath(raw)
        if (not path.parts or path.is_absolute() or path.as_posix() != raw or
                any(part in (".", "..") for part in path.parts)):
            raise ValueError("ngtcp2: unsafe pinned patch path")
        expected.append("../" + raw)
    if (not expected or len(set(expected)) != len(expected) or not isinstance(dependency, dict)
            or dependency.get("version") != "=" + pin["version"]
            or dependency.get("embed") is not True or dependency.get("patches") != expected):
        raise ValueError("ngtcp2: production dependency differs from pinned ordered patches")


def checked_archive(cache: Path, name: str) -> Path:
    pin = PINS[name]
    if pin["archive"] != pin["url"].rsplit("/", 1)[-1] or pin["revision"] not in pin["url"]:
        raise ValueError(f"{name}: archive, revision and URL disagree")
    path = cache / pin["archive"]
    check_digest(path, pin["sha256"])
    descriptor = (ROOT / pin["descriptor"]).read_text(encoding="utf-8")
    for expected in (f'["{pin["version"]}"]',
                     f'url = "{pin["url"]}"', f'sha256 = "{pin["sha256"]}"'):
        if descriptor.count(expected) != 1:
            raise ValueError(f"{name}: descriptor must contain exactly one {expected}")
    for patch in pin.get("patches", []):
        check_digest(ROOT / patch["path"], patch["sha256"])
    for patch in mcpp_patch_entries(pin):
        check_digest(ROOT / patch["path"], patch["sha256"])
    return path


def archive_file(archive: Path, member: str) -> bytes:
    with tarfile.open(archive, "r:*") as src:
        handle = src.extractfile(member)
        if handle is None:
            raise ValueError(f"{archive}: missing {member}")
        return handle.read()


def generated(descriptor: bytes, path: str, left: bytes, right: bytes) -> bytes:
    prefix = b'["' + path.encode() + b'"] = ' + left
    if descriptor.count(prefix) != 1:
        raise ValueError(f"{path}: expected exactly one generated file declaration")
    return descriptor.split(prefix, 1)[1].split(right, 1)[0]


def verify_headers(archives: dict[str, Path], name: str, directory: Path) -> None:
    pin = PINS[name]
    inputs = ["include/" + header for header in HEADERS[name]]
    for relative in inputs:
        data = archive_file(archives[name], f'{name}-{pin["revision"]}/{relative}')
        # The Corosio archive stores this file as CRLF; its patch targets LF.
        if name == "corosio":
            data = data.replace(b"\r\n", b"\n")
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for patch in pin["patches"]:
        patch_file = ROOT / patch["path"]
        check_digest(patch_file, patch["sha256"])
        subprocess.run(["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch_file)],
                       cwd=directory, check=True, capture_output=True, text=True)
    exact = directory.parent / (name + "-exact")
    exact.mkdir()
    for relative in inputs:
        target=exact / pin["source_root"] / relative
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(archive_file(archives[name],pin["source_root"] + "/" + relative))
    subprocess.run(["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(ROOT / pin["mcpp_patch"]["path"])], cwd=exact,check=True,capture_output=True,text=True)
    for relative in inputs:
        actual = (exact / pin["source_root"] / relative).read_bytes()
        if actual != (directory / relative).read_bytes():
            raise ValueError(f"{name}: generated {relative} differs from pinned source plus patches")


def verify_boringssl_native(archives: dict[str, Path], directory: Path) -> None:
    pin = PINS["boringssl"]
    inputs = ("crypto/x509/x_name.cc", "crypto/x509/x_pubkey.cc")
    for relative in inputs:
        original = archive_file(archives["boringssl"], pin["source_root"] + "/" + relative)
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(original)
    for patch in pin["patches"]:
        patch_file = ROOT / patch["path"]
        check_digest(patch_file, patch["sha256"])
        subprocess.run(["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch_file)],
                       cwd=directory, check=True, capture_output=True, text=True)
    descriptor = (ROOT / pin["descriptor"]).read_bytes()
    source_list = descriptor.split(b"    sources = {", 1)[1].split(b"    targets =", 1)[0]
    exact = directory / "exact"
    for relative in inputs:
        target = exact / pin["source_root"] / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive_file(archives["boringssl"], pin["source_root"] + "/" + relative))
    subprocess.run(["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i",
                    str(ROOT / "3rdparty/patches/boringssl/mcpp-exact.patch")],
                   cwd=exact, check=True, capture_output=True)
    for relative in inputs:
        if (exact / pin["source_root"] / relative).read_bytes() != (directory / relative).read_bytes():
            raise ValueError("boringssl: exact patch differs from original patches: " + relative)
        if source_list.count(('"*/' + relative + '"').encode()) != 1:
            raise ValueError("boringssl: native source must have exactly one provider")


def verify_generated_descriptor(name: str, script: str, archives: dict[str, Path]) -> None:
    module = runpy.run_path(str(ROOT / script))
    pin = PINS[name]
    revision = module["VERSION"] if name == "nghttp2" else module["REVISION"]
    if revision != pin["revision"] or module["SHA256"] != pin["sha256"]:
        raise ValueError(f"{name}: source-list generator and independent pin disagree")
    if module["descriptor"](archives[name]) != (ROOT / pin["descriptor"]).read_text(encoding="utf-8"):
        raise ValueError(f"{name}: descriptor differs from verified source list")


def verify_blake3(archive: Path) -> None:
    pin = PINS["blake3"]
    prefix = f'BLAKE3-{pin["revision"]}/c/'
    cmake = archive_file(archive, prefix + "CMakeLists.txt").decode("utf-8")
    library = re.findall(r"add_library\(blake3\s+(.*?)\)", cmake, re.S)
    portable = re.findall(r'elseif\(BLAKE3_SIMD_TYPE STREQUAL "none"\)\s*'
                          r'target_compile_definitions\(blake3 PRIVATE\s+(.*?)\)', cmake, re.S)
    if len(library) != 1 or len(portable) != 1:
        raise ValueError("BLAKE3: cannot determine upstream portable configuration")
    sources, defines = library[0].split(), [d for d in portable[0].split() if d != "BLAKE3_USE_NEON=0"]
    descriptor = (ROOT / pin["descriptor"]).read_text(encoding="utf-8")
    lists = [re.findall(rf'\b{field}\s*=\s*\{{(.*?)\}}', descriptor, re.S)
             for field in ("sources", "defines")]
    if any(len(item) != 1 for item in lists):
        raise ValueError("BLAKE3: expected one source list and one define list")
    described_sources = re.findall(r'"\*/c/([^"]+)"', lists[0][0])
    described_defines = re.findall(r'"([^"]+)"', lists[1][0])
    if (described_sources != sources or described_defines != defines
            or '"mcpp_generated/blake3_neon_guard.c"' not in lists[0][0]
            or 'blake3_neon.c' not in descriptor):
        raise ValueError("BLAKE3: descriptor differs from upstream portable/NEON CMake configuration")
    for source in [*sources, "blake3_neon.c"]:
        archive_file(archive, prefix + source)


def verify_quic(archives: dict[str, Path]) -> None:
    source_generator = runpy.run_path(str(ROOT / "scripts/mcpp-quic-sources.py"))
    module_generator = runpy.run_path(str(ROOT / "scripts/mcpp-quic-modules.py"))
    for name in ("ngtcp2", "nghttp3"):
        pin = PINS[name]
        if source_generator["PINS"][name] != (pin["revision"], pin["sha256"]):
            raise ValueError(f"{name}: generator and independent pin disagree")
        if source_generator["descriptor"](name, archives[name]) != (ROOT / pin["descriptor"]).read_text():
            raise ValueError(f"{name}: descriptor differs from verified C-core sources/configuration")
        for path, expected in module_generator["modules"](name, archives[name]).items():
            if path.read_text() != expected:
                raise ValueError(f"{path}: generated ABI module differs from verified upstream header")
        if name == "ngtcp2":
            verify_ngtcp2_manifest(ROOT / "src/mcpp.toml", pin)
            audit = runpy.run_path(str(ROOT / "scripts/mcpp-verify-installed.py"))
            patched, _ = audit["patched_files"](archives[name], pin)
            conn = patched["lib/ngtcp2_conn.c"]
            for symbol in (b"int nexus_ngtcp2_restart_pmtud(", b"int nexus_ngtcp2_set_brutal("):
                if conn.count(symbol) != 1:
                    raise ValueError(f"ngtcp2: patched source does not define exactly one {symbol!r}")
        for bundled in pin.get("bundled_sources", []):
            for path, expected in bundled["files"].items():
                actual = hashlib.sha256(archive_file(archives[name], pin["source_root"] + "/" + path)).hexdigest()
                if actual != expected:
                    raise ValueError(f"{name}: bundled dependency {path} differs from pinned revision")


def verify_argon2(archive: Path) -> None:
    pin=PINS["argon2"]
    descriptor=(ROOT/pin["descriptor"]).read_text(encoding="utf-8")
    names=(ROOT/"3rdparty/argon2/symbols.txt").read_text(encoding="utf-8").splitlines()
    if len(names)!=49 or len(set(names))!=49 or names!=sorted(names) or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",n) for n in names):
        raise ValueError("argon2: invalid symbol namespace list")
    match=re.search(r"defines\s*=\s*\{([^}]*)\}",descriptor)
    if not match:raise ValueError("argon2: defines absent")
    defines=re.findall(r'"([^"\n]+)"',match.group(1))
    expected=["ARGON2_NO_THREADS"]+[f"{name}=nexus_snell_{name}" for name in names]
    if defines!=expected:raise ValueError("argon2: collision namespace definitions differ")
    expected_sources=["argon2.c","core.c","blake2/blake2b.c","thread.c","encoding.c","ref.c"]
    match=re.search(r"sources\s*=\s*\{([^}]*)\}",descriptor)
    if not match or re.findall(r'"([^"\n]+)"',match.group(1))!=[f"*/src/{name}" for name in expected_sources]:
        raise ValueError("argon2: unexpected source set")
    for path in ["LICENSE","include/argon2.h",*[f"src/{name}" for name in expected_sources]]:
        archive_file(archive,f'{pin["source_root"]}/{path}')
    if 'licenses = { "Apache-2.0" }' not in descriptor or 'c_standard = "gnu11"' not in descriptor or 'generated_files' in descriptor:
        raise ValueError("argon2: unexpected license, C mode or generated overlay")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=CACHE,
                        help="directory containing all pinned upstream archives")
    args = parser.parse_args()
    archives = {name: checked_archive(args.cache, name) for name in PINS}
    with tempfile.TemporaryDirectory(prefix="nexus-mcpp-pins-") as tmp:
        for name in HEADERS:
            directory = Path(tmp) / name
            directory.mkdir()
            verify_headers(archives, name, directory)
        verify_boringssl_native(archives, Path(tmp) / "boringssl")
    proxy = PINS["proxy"]
    module = archive_file(archives["proxy"], f'proxy-{proxy["revision"]}/include/proxy/v4/proxy.ixx')
    if generated((ROOT / proxy["descriptor"]).read_bytes(),
                 "mcpp_generated/proxy.cppm", b"[=[", b"]=]") != module:
        raise ValueError("ngcpp/proxy: generated module differs from pinned proxy.ixx")
    glaze = PINS["glaze"]
    for header in ("glaze/kdl.hpp", "glaze/beve.hpp"):
        archive_file(archives["glaze"], f'{glaze["source_root"]}/include/{header}')
    beman_iv = PINS["beman_inplace_vector"]
    for header in ("beman/inplace_vector/config.hpp", "beman/inplace_vector/inplace_vector.hpp"):
        archive_file(archives["beman_inplace_vector"], f'{beman_iv["source_root"]}/include/{header}')
    verify_generated_descriptor("corosio", "scripts/mcpp-corosio-sources.py", archives)
    verify_blake3(archives["blake3"])
    verify_argon2(archives["argon2"])
    verify_generated_descriptor("boringssl", "scripts/mcpp-boringssl-sources.py", archives)
    verify_generated_descriptor("nghttp2", "scripts/mcpp-nghttp2-sources.py", archives)
    verify_quic(archives)
    print("mcpp pins, patches, interfaces and generated source lists match verified upstream archives")


if __name__ == "__main__":
    main()
