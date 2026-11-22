#!/usr/bin/env python3
"""Verify profile-sidecar feature isolation and multi-platform mcpp-index descriptors."""

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SIDECAR = {"profile-sidecar", "ssh", "naive", "control-http", "ntp"}
FORBIDDEN_SIDECAR = {
    "io-uring", "ktls", "log-journald", "tproxy-udp", "tun-host-dns", "wireguard-host-dns",
    "acme", "sni-demux", "dns-dhcp", "dns-mdns", "derp-server", "ssmapi",
    "openvpn", "openconnect", "reverse-tunnel", "bridge", "tor",
}


def sidecar_closure(root_pkg: dict) -> set[str]:
    by_name = {item["name"]: item for item in root_pkg["features"]["list"]}
    seen: set[str] = set()
    stack = ["profile-sidecar"]
    while stack:
        feat = stack.pop()
        if feat in seen:
            continue
        seen.add(feat)
        info = by_name.get(feat, {})
        for nxt in info.get("implies", []):
            if "/" not in nxt:
                stack.append(nxt)
    return seen


def check_sidecar_features() -> None:
    proc = subprocess.run(
        ["mcpp", "why", "features", "--format", "json", "--offline", "--locked", "--features", "profile-sidecar"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    payload = json.loads(proc.stdout)
    pkgs = payload.get("data", {}).get("packages", [])
    root_pkg = next(
        (pkg for pkg in pkgs if "profile-sidecar" in pkg.get("features", {}).get("active", [])),
        None,
    )
    if root_pkg is None:
        raise SystemExit("profile-sidecar isolation failed: nexus root package missing from mcpp why output")

    by_name = {item["name"]: item for item in root_pkg["features"]["list"]}
    default_features = {name for name, info in by_name.items() if info.get("default")}
    if default_features != {"io-uring"}:
        raise SystemExit(f"unexpected root default features: {sorted(default_features)}")

    active_root = set(root_pkg["features"]["active"])
    closure = sidecar_closure(root_pkg)
    if active_root - default_features != closure:
        raise SystemExit(
            f"unexpected non-default active features under profile-sidecar: "
            f"extra={sorted(active_root - default_features - closure)}, missing={sorted(closure - active_root)}"
        )

    missing = sorted(REQUIRED_SIDECAR - closure)
    leaked = sorted(FORBIDDEN_SIDECAR & closure)
    if missing or leaked:
        raise SystemExit(f"profile-sidecar isolation failed: missing={missing}, leaked={leaked}")

    for consumer in ("mcpp/android-arm64/mcpp.toml", "mcpp/darwin-arm64/mcpp.toml", "mcpp/windows-x64/mcpp.toml"):
        text = (ROOT / consumer).read_text(encoding="utf-8")
        if "default-features = false" not in text or '"profile-sidecar"' not in text:
            raise SystemExit(f"{consumer}: must select default-features = false and profile-sidecar")
    print(f"profile-sidecar isolation ok ({len(closure)} transitive sidecar features checked)")


def check_index_descriptors() -> None:
    descriptors = sorted((ROOT / "3rdparty/mcpp-index/pkgs/n").glob("*.lua"))
    if not descriptors:
        raise SystemExit("no mcpp-index descriptors found")
    for path in descriptors:
        proc = subprocess.run(["mcpp", "xpkg", "parse", str(path), "--json"],
                              cwd=ROOT, check=True, capture_output=True, text=True)
        info = json.loads(proc.stdout)
        versions = info.get("versions", {})
        for plat in ("linux", "macosx", "windows"):
            if not versions.get(plat):
                raise SystemExit(f"{path}: missing version entry for platform '{plat}'")
    print(f"mcpp-index descriptors ok ({len(descriptors)} packages support linux/macosx/windows)")


if __name__ == "__main__":
    check_sidecar_features()
    check_index_descriptors()
