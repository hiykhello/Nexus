#!/usr/bin/env bash
set -euo pipefail

# Packages Nexus desktop distribution archives with optional GPG detached signing.
# Usage:
#   ./packaging/desktop/package-desktop.sh [--dry-run] [--gpg-key <id>] --core <path> [--desktop <path>] [--out-dir <dir>]

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CORE_BIN=""
DESKTOP_BIN=""
WINTUN_DLL=""
OUT_DIR="$ROOT/target/desktop-packages"
VERSION="0.1.0"
GPG_KEY=""
DRY_RUN=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --core) CORE_BIN="${2:?--core requires path}"; shift 2 ;;
        --desktop) DESKTOP_BIN="${2:?--desktop requires path}"; shift 2 ;;
        --wintun) WINTUN_DLL="${2:?--wintun requires path}"; shift 2 ;;
        --out-dir) OUT_DIR="${2:?--out-dir requires dir}"; shift 2 ;;
        --version) VERSION="${2:?--version requires string}"; shift 2 ;;
        --gpg-key) GPG_KEY="${2:?--gpg-key requires key id}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

ARCH="$(uname -m)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
PKG_NAME="nexus-desktop-${VERSION}-${OS}-${ARCH}"

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] package=${PKG_NAME} out_dir=${OUT_DIR} core=${CORE_BIN:-none} desktop=${DESKTOP_BIN:-none}"
    exit 0
fi

[ -n "$CORE_BIN" ] && [ -x "$CORE_BIN" ] || { echo "error: executable --core required" >&2; exit 1; }
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/${PKG_NAME}.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/$PKG_NAME/bin" "$STAGE/$PKG_NAME/systemd"
install -m 0755 "$CORE_BIN" "$STAGE/$PKG_NAME/bin/$(basename "$CORE_BIN")"
[ -n "$DESKTOP_BIN" ] && [ -x "$DESKTOP_BIN" ] && install -m 0755 "$DESKTOP_BIN" "$STAGE/$PKG_NAME/bin/$(basename "$DESKTOP_BIN")"
[ -n "$WINTUN_DLL" ] && [ -f "$WINTUN_DLL" ] && install -m 0644 "$WINTUN_DLL" "$STAGE/$PKG_NAME/bin/wintun.dll"
install -m 0644 "$ROOT/packaging/systemd/nexus.service" "$STAGE/$PKG_NAME/systemd/nexus.service"

mkdir -p "$OUT_DIR"
ARCHIVE="$OUT_DIR/${PKG_NAME}.tar.gz"
tar -C "$STAGE" -czf "$ARCHIVE" "$PKG_NAME"
(cd "$OUT_DIR" && sha256sum "${PKG_NAME}.tar.gz" > "${PKG_NAME}.tar.gz.sha256")
if [ -n "$GPG_KEY" ]; then
    gpg --batch --yes --armor --detach-sign --local-user "$GPG_KEY" "$ARCHIVE"
fi
echo "Packaged: $ARCHIVE"
