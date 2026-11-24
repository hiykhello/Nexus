#!/usr/bin/env python3
"""Verify profile-sidecar/embedded isolation, multi-platform mcpp-index, and portable sources."""

import json
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_EMBEDDED = {
    "profile-embedded", "vless", "trojan", "ss2022", "anytls",
    "hy2-cli", "tuic", "wireguard-outbound", "dns-https", "dns-fakeip", "srs",
}
REQUIRED_SIDECAR = (REQUIRED_EMBEDDED - {"profile-embedded"}) | {
    "profile-sidecar", "ssh", "naive", "control-http", "ntp", "xhttp-vless", "grpc-vless",
}
FORBIDDEN_SIDECAR = {
    "io-uring", "ktls", "log-journald", "tproxy-udp", "tun-host-dns", "wireguard-host-dns",
    "acme", "sni-demux", "dns-dhcp", "dns-mdns", "derp-server", "ssmapi",
    "openvpn", "openconnect", "reverse-tunnel", "bridge", "tor", "masque-ip-server",
}
FORBIDDEN_EMBEDDED = FORBIDDEN_SIDECAR | {
    "tls-certificate-compression", "masque-ip-endpoint", "xhttp-vless", "grpc-vless",
    "snell", "shadowtls-proxy", "ssh", "naive", "control-http", "metrics-openmetrics",
    "ntp", "dns-https3", "http-client-h3",
}


def profile_closure(root_pkg: dict, root_feature: str) -> set[str]:
    by_name = {item["name"]: item for item in root_pkg["features"]["list"]}
    seen: set[str] = set()
    stack = [root_feature]
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
    for profile, required, expected_forbidden in (
        ("profile-sidecar", REQUIRED_SIDECAR, FORBIDDEN_SIDECAR),
        ("profile-embedded", REQUIRED_EMBEDDED, FORBIDDEN_EMBEDDED),
    ):
        proc = subprocess.run(
            ["mcpp", "why", "features", "--format", "json", "--offline", "--locked", "--features", profile],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        payload = json.loads(proc.stdout)
        pkgs = payload.get("data", {}).get("packages", [])
        root_pkg = next(
            (pkg for pkg in pkgs if profile in pkg.get("features", {}).get("active", [])),
            None,
        )
        if root_pkg is None:
            raise SystemExit(f"{profile} isolation failed: nexus root package missing from mcpp why output")

        by_name = {item["name"]: item for item in root_pkg["features"]["list"]}
        default_features = {name for name, info in by_name.items() if info.get("default")}
        if default_features != {"io-uring"}:
            raise SystemExit(f"unexpected root default features: {sorted(default_features)}")

        active_root = set(root_pkg["features"]["active"])
        closure = profile_closure(root_pkg, profile)
        if active_root - default_features != closure:
            raise SystemExit(
                f"unexpected non-default active features under {profile}: "
                f"extra={sorted(active_root - default_features - closure)}, missing={sorted(closure - active_root)}"
            )

        missing = sorted(required - closure)
        leaked = sorted(expected_forbidden & closure)
        if missing or leaked:
            raise SystemExit(f"{profile} isolation failed: missing={missing}, leaked={leaked}")

    for consumer, expected_feature in (
        ("mcpp/android-arm64/mcpp.toml", "profile-sidecar"),
        ("mcpp/darwin-arm64/mcpp.toml", "profile-sidecar"),
        ("mcpp/windows-x64/mcpp.toml", "profile-sidecar"),
        ("mcpp/ios-arm64/mcpp.toml", "profile-embedded"),
    ):
        data = tomllib.loads((ROOT / consumer).read_text(encoding="utf-8"))
        nexus_dep = data.get("dependencies", {}).get("nexus", {})
        if nexus_dep.get("default-features") is not False or expected_feature not in nexus_dep.get("features", []):
            raise SystemExit(f"{consumer}: must select default-features = false and {expected_feature}")
    print("profile-sidecar & profile-embedded isolation ok")


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


def has_unguarded_linux_only(path: Path) -> str | None:
    linux_stack: list[bool] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#if"):
            is_linux_guard = "__linux__" in stripped and "!" not in stripped
            linux_stack.append(is_linux_guard or (bool(linux_stack) and linux_stack[-1]))
        elif stripped.startswith("#elif"):
            if linux_stack:
                linux_stack[-1] = "__linux__" in stripped and "!" not in stripped
        elif stripped.startswith("#else"):
            if linux_stack:
                linux_stack[-1] = False
        elif stripped.startswith("#endif"):
            if linux_stack:
                linux_stack.pop()
        elif not any(linux_stack):
            if re.match(r'^#include\s+<linux/', stripped) or stripped.startswith("#error"):
                return f"{path}:{lineno}: unguarded Linux-only directive in unconditional build: {stripped}"
    return None


def check_portable_sources() -> None:
    for pkg_toml in ("src/platform/mcpp.toml", "src/tun/mcpp.toml"):
        pkg_dir = (ROOT / pkg_toml).parent
        data = tomllib.loads((ROOT / pkg_toml).read_text(encoding="utf-8"))
        for pattern in data.get("build", {}).get("sources", []):
            matches = sorted(pkg_dir.glob(pattern)) if "*" in pattern else [pkg_dir / pattern]
            if not matches:
                raise SystemExit(f"{pkg_toml}: unmatched source pattern '{pattern}'")
            for src in matches:
                if err := has_unguarded_linux_only(src):
                    raise SystemExit(err)
    print("portable build sources ok (platform & tun)")


def check_subproject_opt_profiles() -> None:
    expected_size = {"opt": "z", "lto": True, "strip": True}
    expected_speed = {"opt": 3, "lto": True, "strip": True}
    root_data = tomllib.loads((ROOT / "mcpp.toml").read_text(encoding="utf-8"))
    ws_profile = root_data.get("workspace", {}).get("profile", {})
    if ws_profile.get("release") != expected_size:
        raise SystemExit(f"mcpp.toml: unexpected [workspace.profile.release]: {ws_profile.get('release')!r}")
    if ws_profile.get("size") != expected_size:
        raise SystemExit(f"mcpp.toml: unexpected [workspace.profile.size]: {ws_profile.get('size')!r}")
    if ws_profile.get("speed") != expected_speed:
        raise SystemExit(f"mcpp.toml: unexpected [workspace.profile.speed]: {ws_profile.get('speed')!r}")

    entrypoints = (
        "mcpp/epoll/mcpp.toml",
        "mcpp/android-arm64/mcpp.toml",
        "mcpp/ios-arm64/mcpp.toml",
        "mcpp/darwin-arm64/mcpp.toml",
        "mcpp/windows-x64/mcpp.toml",
        "mcpp/host-consumer/mcpp.toml",
    )
    for manifest in entrypoints:
        data = tomllib.loads((ROOT / manifest).read_text(encoding="utf-8"))
        profile = data.get("profile", {})
        if profile.get("release") != expected_size:
            raise SystemExit(f"{manifest}: unexpected [profile.release]: {profile.get('release')!r}")
        if profile.get("size") != expected_size:
            raise SystemExit(f"{manifest}: unexpected [profile.size]: {profile.get('size')!r}")
        if profile.get("speed") != expected_speed:
            raise SystemExit(f"{manifest}: unexpected [profile.speed]: {profile.get('speed')!r}")
    print(f"workspace & subproject optimization profiles ok ({len(entrypoints)} entrypoints)")


if __name__ == "__main__":
    check_sidecar_features()
    check_subproject_opt_profiles()
    check_index_descriptors()
    check_portable_sources()
