#!/usr/bin/env python3
"""Generate named C ABI modules from verified ngtcp2/nghttp3 release headers.

The header's C declarations are preserved, including callback types and exact
versioned structs. System includes are replaced by imported std scalar types;
ngtcp2's upstream generic address structs represent the verified Linux ABI.
Neither the generated modules nor their consumers use textual includes.
"""

import argparse
import json
from pathlib import Path
import re
import runpy
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "3rdparty/quic-boundary.json"
CORE = runpy.run_path(str(ROOT / "scripts/mcpp-quic-sources.py"))


def modules(name: str, archive: Path, compiler: str = "/usr/bin/g++") -> dict[Path, str]:
    # Check the full archive and its C-core source list before reading headers.
    CORE["descriptor"](name, archive)
    version = CORE["PINS"][name][0]
    spec = json.loads(SPEC.read_text())[name]
    with tarfile.open(archive, "r:xz") as tar:
        prefix = f"{name}-{version}/lib/includes/{name}/"
        header = tar.extractfile(prefix + name + ".h").read().decode()
        version_header = tar.extractfile(prefix + "version.h").read().decode()
    license_text = header[:header.index("*/") + 2]
    # Preprocessing still selects the exact upstream declarations. It performs
    # no type substitution or hand-maintained struct/callback reconstruction.
    header = re.sub(r"^\s*#\s*include[^\n]*", "", header, flags=re.M)
    constants = "\n".join(f"inline constexpr auto {key} = {macro};"
                          for key, macro in spec["macro_exports"].items())
    flags = [f"-D{name.upper()}_STATICLIB"]
    if name == "ngtcp2":
        flags.extend(["-DNGTCP2_USE_GENERIC_SOCKADDR", "-DNGTCP2_AF_INET=2", "-DNGTCP2_AF_INET6=10"])
    body = subprocess.run([compiler, "-E", "-P", "-x", "c++", *flags, "-"],
                          input=version_header + "\n" + header + "\n" + constants + "\n",
                          check=True, capture_output=True, text=True).stdout
    if name == "ngtcp2":
        sockaddr_pattern = (
            r"typedef unsigned short int ngtcp2_sa_family;\n"
            r"typedef uint16_t ngtcp2_in_port;\n"
            r"typedef struct ngtcp2_sockaddr \{.*?"
            r"\} ngtcp2_sockaddr_in6;"
        )
        sockaddr_replacement = """#if defined(__APPLE__)
typedef uint8_t ngtcp2_sa_family;
typedef uint16_t ngtcp2_in_port;
typedef struct ngtcp2_sockaddr {
  uint8_t sa_len;
  ngtcp2_sa_family sa_family;
  uint8_t sa_data[14];
} ngtcp2_sockaddr;
typedef struct ngtcp2_in_addr {
  uint32_t s_addr;
} ngtcp2_in_addr;
typedef struct ngtcp2_sockaddr_in {
  uint8_t sin_len;
  ngtcp2_sa_family sin_family;
  ngtcp2_in_port sin_port;
  ngtcp2_in_addr sin_addr;
  uint8_t sin_zero[8];
} ngtcp2_sockaddr_in;
typedef struct alignas(4) ngtcp2_in6_addr {
  uint8_t s6_addr[16];
} ngtcp2_in6_addr;
typedef struct ngtcp2_sockaddr_in6 {
  uint8_t sin6_len;
  ngtcp2_sa_family sin6_family;
  ngtcp2_in_port sin6_port;
  uint32_t sin6_flowinfo;
  ngtcp2_in6_addr sin6_addr;
  uint32_t sin6_scope_id;
} ngtcp2_sockaddr_in6;
#elif defined(_WIN32)
typedef uint16_t ngtcp2_sa_family;
typedef uint16_t ngtcp2_in_port;
typedef struct ngtcp2_sockaddr {
  ngtcp2_sa_family sa_family;
  uint8_t sa_data[14];
} ngtcp2_sockaddr;
typedef struct ngtcp2_in_addr {
  uint32_t s_addr;
} ngtcp2_in_addr;
typedef struct ngtcp2_sockaddr_in {
  ngtcp2_sa_family sin_family;
  ngtcp2_in_port sin_port;
  ngtcp2_in_addr sin_addr;
  uint8_t sin_zero[8];
} ngtcp2_sockaddr_in;
typedef struct alignas(2) ngtcp2_in6_addr {
  uint8_t s6_addr[16];
} ngtcp2_in6_addr;
typedef struct ngtcp2_sockaddr_in6 {
  ngtcp2_sa_family sin6_family;
  ngtcp2_in_port sin6_port;
  uint32_t sin6_flowinfo;
  ngtcp2_in6_addr sin6_addr;
  uint32_t sin6_scope_id;
} ngtcp2_sockaddr_in6;
#else
typedef unsigned short int ngtcp2_sa_family;
typedef uint16_t ngtcp2_in_port;
typedef struct ngtcp2_sockaddr {
  ngtcp2_sa_family sa_family;
  uint8_t sa_data[14];
} ngtcp2_sockaddr;
typedef struct ngtcp2_in_addr {
  uint32_t s_addr;
} ngtcp2_in_addr;
typedef struct ngtcp2_sockaddr_in {
  ngtcp2_sa_family sin_family;
  ngtcp2_in_port sin_port;
  ngtcp2_in_addr sin_addr;
  uint8_t sin_zero[8];
} ngtcp2_sockaddr_in;
typedef struct __attribute__((aligned(4))) ngtcp2_in6_addr {
  uint8_t s6_addr[16];
} ngtcp2_in6_addr;
typedef struct ngtcp2_sockaddr_in6 {
  ngtcp2_sa_family sin6_family;
  ngtcp2_in_port sin6_port;
  uint32_t sin6_flowinfo;
  ngtcp2_in6_addr sin6_addr;
  uint32_t sin6_scope_id;
} ngtcp2_sockaddr_in6;
#endif"""
        body, count = re.subn(sockaddr_pattern, sockaddr_replacement, body, flags=re.S)
        if count != 1:
            raise ValueError("upstream generic sockaddr representation changed")
        af6_replacement = (
            "#if defined(__APPLE__)\n"
            "inline constexpr auto af_inet6 = 30;\n"
            "#elif defined(_WIN32)\n"
            "inline constexpr auto af_inet6 = 23;\n"
            "#else\n"
            "inline constexpr auto af_inet6 = 10;\n"
            "#endif"
        )
        body, count6 = re.subn(r"inline constexpr auto af_inet6 = 10;", af6_replacement, body)
        if count6 != 1:
            raise ValueError("upstream af_inet6 macro constant changed")
    if re.search(r"^\s*#\s*include\b", body, re.M):
        raise ValueError("generated module contains a textual include")
    scalars = ("size_t", "ptrdiff_t", "va_list", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
               "int8_t", "int16_t", "int32_t", "int64_t")
    aliases = "\n".join(f"using std::{scalar};" for scalar in scalars)
    abi = f'''// Generated by scripts/mcpp-quic-modules.py; do not edit.
{license_text}
module;
#if !(defined(__linux__) || defined(__APPLE__) || defined(_WIN32)) || !(defined(__LP64__) || defined(_WIN64))
#error "This generated C ABI requires 64-bit Linux, Apple Darwin, or Windows"
#endif
export module {name};
import std;
export namespace {name}_abi {{
{aliases}
{body}}}
'''
    names = spec["types"] + spec["functions"] + spec.get("enum_values", [])
    names += list(spec["macro_exports"])
    exports = "\n".join(f"    using {name}_abi::{symbol};" for symbol in names)
    wrapper = f'''export namespace {name} {{
{exports}
}}
'''
    # Keep declarations and selected aliases in one BMI. GCC 16 fails to load
    # some C struct clusters when their aliases cross a second module boundary.
    return {ROOT / f"3rdparty/modules/{name}.cppm": abi + "\n" + wrapper}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", choices=CORE["PINS"])
    parser.add_argument("archive", type=Path)
    parser.add_argument("--compiler", default="/usr/bin/g++")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    for path, expected in modules(args.name, args.archive, args.compiler).items():
        if args.write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected)
        elif path.read_text() != expected:
            raise ValueError(f"{path}: stale generated module")
    print(f"{args.name} named C ABI module matches verified upstream declarations")


if __name__ == "__main__":
    main()
