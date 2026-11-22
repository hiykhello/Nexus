#!/usr/bin/env bash
set -euo pipefail

# Packages a Linux release tarball bundling the Nexus binary, hardened systemd units,
# Shell completions (bash/zsh/fish), and SHA256SUMS manifest.
#
# Usage:
#   ./scripts/package-linux-release.sh [--desktop <desktop-bin>] <binary-path> [version] [arch] [output-dir]

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DESKTOP_BIN=""
POS=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --desktop)
            DESKTOP_BIN="${2:?--desktop requires path to nexus-desktop binary}"
            shift 2
            ;;
        --desktop=*)
            DESKTOP_BIN="${1#*=}"
            shift
            ;;
        *)
            POS+=("$1")
            shift
            ;;
    esac
done

BIN="${POS[0]:?usage: $0 [--desktop <desktop-bin>] <binary-path> [version] [arch] [output-dir]}"
VERSION="${POS[1]:-0.1.0}"
ARCH="${POS[2]:-$(uname -m)}"
OUT_DIR="${POS[3]:-$ROOT/target/release-packages}"

if [ ! -x "$BIN" ]; then
    echo "error: executable binary not found: $BIN" >&2
    exit 1
fi
if [ -n "$DESKTOP_BIN" ] && [ ! -x "$DESKTOP_BIN" ]; then
    echo "error: executable desktop binary not found: $DESKTOP_BIN" >&2
    exit 1
fi

PKG_NAME="nexus-${VERSION}-linux-${ARCH}"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/${PKG_NAME}.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p \
    "$STAGE/$PKG_NAME/bin" \
    "$STAGE/$PKG_NAME/systemd" \
    "$STAGE/$PKG_NAME/openwrt" \
    "$STAGE/$PKG_NAME/completions"

install -m 0755 "$BIN" "$STAGE/$PKG_NAME/bin/nexus"
if [ -n "$DESKTOP_BIN" ]; then
    install -m 0755 "$DESKTOP_BIN" "$STAGE/$PKG_NAME/bin/nexus-desktop"
    mkdir -p "$STAGE/$PKG_NAME/share/applications"
    cat > "$STAGE/$PKG_NAME/share/applications/nexus-desktop.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Nexus
Comment=Nexus Proxy Desktop Controller
Exec=nexus-desktop
Terminal=false
Categories=Network;Utility;
EOF
fi
install -m 0644 "$ROOT/packaging/systemd/nexus.service" "$STAGE/$PKG_NAME/systemd/nexus.service"
install -m 0644 "$ROOT/packaging/systemd/nexus@.service" "$STAGE/$PKG_NAME/systemd/nexus@.service"
install -m 0755 "$ROOT/packaging/openwrt/nexus.init" "$STAGE/$PKG_NAME/openwrt/nexus.init"
install -m 0644 "$ROOT/packaging/openwrt/Makefile" "$STAGE/$PKG_NAME/openwrt/Makefile"
install -m 0644 "$ROOT/packaging/completions/nexus.bash" "$STAGE/$PKG_NAME/completions/nexus.bash"
install -m 0644 "$ROOT/packaging/completions/_nexus" "$STAGE/$PKG_NAME/completions/_nexus"
install -m 0644 "$ROOT/packaging/completions/nexus.fish" "$STAGE/$PKG_NAME/completions/nexus.fish"
install -m 0644 "$ROOT/packaging/README.md" "$STAGE/$PKG_NAME/README.md"

mkdir -p "$OUT_DIR"
TARBALL="$OUT_DIR/${PKG_NAME}.tar.gz"
tar -C "$STAGE" -czf "$TARBALL" "$PKG_NAME"
(cd "$OUT_DIR" && sha256sum "${PKG_NAME}.tar.gz" > "${PKG_NAME}.tar.gz.sha256")
echo "Packaged: $TARBALL"
echo "Checksum: $(cat "$OUT_DIR/${PKG_NAME}.tar.gz.sha256")"
