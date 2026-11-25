#!/usr/bin/env bash
set -euo pipefail

# Batch 158/170 offline release pipeline using mcpp fetch --to / --from + mcpp pack --offline --locked.
# Usage:
#   ./scripts/release-offline-bundle.sh [--dry-run] [--bundle-dir <dir>] [--out-dir <dir>] [--profile <feat>] [--opt-profile <size|release|speed>] [--version <v>]

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUNDLE_DIR="$ROOT/target/offline-bundle"
OUT_DIR="$ROOT/target/release-packages"
PROFILE="profile-linux-uring"
OPT_PROFILE="size"
VERSION="0.1.0"
DRY_RUN=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --bundle-dir) BUNDLE_DIR="${2:?--bundle-dir requires path}"; shift 2 ;;
        --out-dir) OUT_DIR="${2:?--out-dir requires path}"; shift 2 ;;
        --profile) PROFILE="${2:?--profile requires feature}"; shift 2 ;;
        --opt-profile) OPT_PROFILE="${2:?--opt-profile requires size|release|speed}"; shift 2 ;;
        --version) VERSION="${2:?--version requires version}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help)
            sed -n '4,6p' "$0"
            exit 0
            ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

case "$OPT_PROFILE" in
    size|release|speed) ;;
    *) echo "error: --opt-profile must be size, release, or speed, got '$OPT_PROFILE'" >&2; exit 2 ;;
esac

LOCK_FILE="$ROOT/mcpp/epoll/mcpp.lock"
EXPECTED_LOCK_SHA="5da3ae56d02ac0811654c4123958477182ea78d7652d74d82687c7cc92b18b5b"
ACTUAL_LOCK_SHA="$(sha256sum "$LOCK_FILE" | awk '{print $1}')"
if [ "$ACTUAL_LOCK_SHA" != "$EXPECTED_LOCK_SHA" ]; then
    echo "error: lockfile digest mismatch before offline release: $ACTUAL_LOCK_SHA" >&2
    exit 1
fi

generate_notices() {
    python3 - "$ROOT" "${1:--}" <<'PY'
import json, pathlib, re, subprocess, sys

root = pathlib.Path(sys.argv[1])
out_arg = sys.argv[2]
descs = sorted((root / "3rdparty/mcpp-index/pkgs/n").glob("nexus.*.lua"))
if len(descs) != 12:
    raise SystemExit(f"expected 12 pinned xpkg descriptors, found {len(descs)}")

lines = ["Nexus Third-Party Pinned Source Notices", ""]
for path in descs:
    raw = path.read_text(encoding="utf-8")
    meta = json.loads(subprocess.check_output(["mcpp", "xpkg", "parse", str(path), "--json"], cwd=root, text=True))
    name = f"{meta.get('namespace', 'nexus')}.{meta['name']}"
    versions = meta.get("versions", {}).get("linux") or []
    lic_m = re.search(r'licenses\s*=\s*\{([^}]*)\}', raw)
    licenses = ", ".join(re.findall(r'"([^"]+)"', lic_m.group(1))) if lic_m else ""
    repo_m = re.search(r'\brepo\s*=\s*"([^"]+)"', raw)
    url_m = re.search(r'\burl\s*=\s*"([^"]+)"', raw)
    sha_m = re.search(r'\bsha256\s*=\s*"([^"]+)"', raw)
    if not versions or not licenses or not repo_m or not url_m or not sha_m:
        raise SystemExit(f"{path}: incomplete notice metadata")
    lines.append(f"- {name} {versions[0]} | License: {licenses}")
    lines.append(f"  Upstream: {repo_m.group(1)}")
    lines.append(f"  Archive:  {url_m.group(1)} (sha256: {sha_m.group(1)})")

text = "\n".join(lines) + "\n"
if out_arg != "-":
    pathlib.Path(out_arg).write_text(text, encoding="utf-8")
else:
    print(f"verified {len(descs)} third-party notices", end="")
PY
}

ARCH="$(uname -m)"
if [ "$DRY_RUN" -eq 1 ]; then
    NOTICE_STATUS="$(generate_notices -)"
    echo "[dry-run] lock_sha256=$ACTUAL_LOCK_SHA"
    echo "[dry-run] step 1: mcpp fetch --locked --features $PROFILE --to $BUNDLE_DIR"
    echo "[dry-run] step 2: mcpp fetch --from $BUNDLE_DIR --locked --features $PROFILE"
    echo "[dry-run] step 3: mcpp pack --offline --locked --profile $OPT_PROFILE --features $PROFILE --pkg-format dir"
    echo "[dry-run] step 4: generate THIRD_PARTY_NOTICES.txt ($NOTICE_STATUS)"
    echo "[dry-run] step 5: sha256sum bundle -> $OUT_DIR/nexus-${VERSION}-${ARCH}-${PROFILE}-${OPT_PROFILE}.tar.gz"
    exit 0
fi

mkdir -p "$BUNDLE_DIR" "$OUT_DIR"
(cd "$ROOT" && mcpp fetch --locked --features "$PROFILE" --to "$BUNDLE_DIR")
(cd "$ROOT" && mcpp fetch --from "$BUNDLE_DIR" --locked --features "$PROFILE")
(cd "$ROOT" && mcpp pack --offline --locked --profile "$OPT_PROFILE" --features "$PROFILE" --pkg-format dir)

PACK_ROOT="$ROOT/target"
STAGED_DIR="$(find "$PACK_ROOT" -maxdepth 4 -type d -name "nexus*" | head -n 1)"
ARCHIVE="$OUT_DIR/nexus-${VERSION}-${ARCH}-${PROFILE}-${OPT_PROFILE}.tar.gz"
if [ -n "$STAGED_DIR" ]; then
    generate_notices "$STAGED_DIR/THIRD_PARTY_NOTICES.txt"
    tar -C "$(dirname "$STAGED_DIR")" -czf "$ARCHIVE" "$(basename "$STAGED_DIR")"
    (cd "$OUT_DIR" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
    echo "Offline release packaged: $ARCHIVE"
fi
