#!/usr/bin/env bash
set -euo pipefail

# Packages macOS arm64 + iOS arm64 Nexus static C-ABI libraries into NexusCore.xcframework.
# Usage:
#   ./scripts/build-apple-xcframework.sh [--dry-run] [--out-dir <dir>]

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/target/apple"
DRY_RUN=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --out-dir) OUT_DIR="${2:?--out-dir requires path}"; shift 2 ;;
        -h|--help)
            sed -n '4,6p' "$0"
            exit 0
            ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

HEADER="$ROOT/include/nexus/core_c_api.h"
if [ ! -f "$HEADER" ]; then
    echo "error: missing C ABI header: $HEADER" >&2
    exit 1
fi

for manifest in "$ROOT/mcpp/darwin-arm64/mcpp.toml" "$ROOT/mcpp/ios-arm64/mcpp.toml"; do
    if [ ! -f "$manifest" ]; then
        echo "error: missing Apple mcpp consumer manifest: $manifest" >&2
        exit 1
    fi
done

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] step 1: (cd mcpp/darwin-arm64 && mcpp --offline --locked build --release --strict)"
    echo "[dry-run] step 2: (cd mcpp/ios-arm64 && mcpp --offline --locked build --release --strict)"
    echo "[dry-run] step 3: stage $HEADER + module.modulemap (NexusCoreC)"
    echo "[dry-run] step 4: xcodebuild -create-xcframework -> $OUT_DIR/NexusCore.xcframework"
    exit 0
fi

if [ "$(uname -s)" != "Darwin" ] || ! command -v xcodebuild >/dev/null 2>&1; then
    echo "error: Apple XCFramework packaging requires macOS with xcodebuild installed" >&2
    exit 1
fi
if ! command -v mcpp >/dev/null 2>&1; then
    echo "error: mcpp toolchain is required to build nexus-core-apple and nexus-core-ios" >&2
    exit 1
fi

(cd "$ROOT/mcpp/darwin-arm64" && mcpp --offline --locked build --release --strict)
(cd "$ROOT/mcpp/ios-arm64" && mcpp --offline --locked build --release --strict)

MACOS_LIB="$(find "$ROOT/target" -name 'libnexus_core*.a' -path '*aarch64-macos*' | head -n 1)"
IOS_LIB="$(find "$ROOT/target" -name 'libnexus_core*.a' -path '*aarch64-ios*' | head -n 1)"
if [ -z "$MACOS_LIB" ] || [ -z "$IOS_LIB" ]; then
    echo "error: failed to locate built static libraries for macOS ($MACOS_LIB) or iOS ($IOS_LIB)" >&2
    exit 1
fi

STAGE="$OUT_DIR/stage"
HDR_DIR="$STAGE/headers/NexusCoreC"
rm -rf "$STAGE" "$OUT_DIR/NexusCore.xcframework"
mkdir -p "$HDR_DIR"
cp "$HEADER" "$HDR_DIR/core_c_api.h"
cat > "$HDR_DIR/module.modulemap" <<'EOF'
module NexusCoreC {
    header "core_c_api.h"
    export *
}
EOF

xcodebuild -create-xcframework \
    -library "$MACOS_LIB" -headers "$STAGE/headers" \
    -library "$IOS_LIB" -headers "$STAGE/headers" \
    -output "$OUT_DIR/NexusCore.xcframework"

echo "Packaged Apple XCFramework: $OUT_DIR/NexusCore.xcframework"
