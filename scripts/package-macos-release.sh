#!/usr/bin/env bash
set -euo pipefail

# Packages a macOS release tarball bundling nexus CLI, optional libnexus_core.a,
# C-API header, launchd plist template, shell completions, and SHA-256 manifest.
#
# Usage:
#   ./scripts/package-macos-release.sh [--dry-run] [--lib <lib-path>] [--desktop <app-bin>] <binary-path> [version] [arch] [output-dir]

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRY_RUN=0
LIB_PATH=""
DESKTOP_BIN=""
POS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --lib) LIB_PATH="${2:?--lib requires path}"; shift 2 ;;
        --desktop) DESKTOP_BIN="${2:?--desktop requires path}"; shift 2 ;;
        *) POS+=("$1"); shift ;;
    esac
done

VERSION="${POS[1]:-0.1.0}"
ARCH="${POS[2]:-arm64}"
OUT_DIR="${POS[3]:-$ROOT/target/release-packages}"
PKG_NAME="nexus-${VERSION}-darwin-${ARCH}"

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] stage $PKG_NAME in $OUT_DIR/${PKG_NAME}.tar.gz"
    echo "[dry-run] include: bin/nexus, include/nexus/core_c_api.h, launchd/io.nexus.proxy.plist, completions/*"
    exit 0
fi

BIN="${POS[0]:?usage: $0 [--dry-run] [--lib <lib-path>] [--desktop <app-bin>] <binary-path> [version] [arch] [output-dir]}"
if [ ! -x "$BIN" ]; then
    echo "error: executable binary not found: $BIN" >&2
    exit 1
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/${PKG_NAME}.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p \
    "$STAGE/$PKG_NAME/bin" \
    "$STAGE/$PKG_NAME/include/nexus" \
    "$STAGE/$PKG_NAME/launchd" \
    "$STAGE/$PKG_NAME/completions"

install -m 0755 "$BIN" "$STAGE/$PKG_NAME/bin/nexus"
if [ -n "$DESKTOP_BIN" ] && [ -x "$DESKTOP_BIN" ]; then
    install -m 0755 "$DESKTOP_BIN" "$STAGE/$PKG_NAME/bin/nexus-desktop"
fi
if [ -n "$LIB_PATH" ] && [ -f "$LIB_PATH" ]; then
    mkdir -p "$STAGE/$PKG_NAME/lib"
    install -m 0644 "$LIB_PATH" "$STAGE/$PKG_NAME/lib/"
fi
install -m 0644 "$ROOT/include/nexus/core_c_api.h" "$STAGE/$PKG_NAME/include/nexus/core_c_api.h"
install -m 0644 "$ROOT/packaging/launchd/io.nexus.proxy.plist" "$STAGE/$PKG_NAME/launchd/io.nexus.proxy.plist"
install -m 0644 "$ROOT/packaging/completions/nexus.bash" "$STAGE/$PKG_NAME/completions/nexus.bash"
install -m 0644 "$ROOT/packaging/completions/_nexus" "$STAGE/$PKG_NAME/completions/_nexus"
install -m 0644 "$ROOT/packaging/completions/nexus.fish" "$STAGE/$PKG_NAME/completions/nexus.fish"
install -m 0644 "$ROOT/packaging/README.md" "$STAGE/$PKG_NAME/README.md"

mkdir -p "$OUT_DIR"
TARBALL="$OUT_DIR/${PKG_NAME}.tar.gz"
tar -C "$STAGE" -czf "$TARBALL" "$PKG_NAME"
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUT_DIR" && sha256sum "${PKG_NAME}.tar.gz" > "${PKG_NAME}.tar.gz.sha256")
else
    (cd "$OUT_DIR" && shasum -a 256 "${PKG_NAME}.tar.gz" > "${PKG_NAME}.tar.gz.sha256")
fi
echo "Packaged: $TARBALL"
