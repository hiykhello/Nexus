#!/usr/bin/env bash
set -euo pipefail

# Batch 158 offline release pipeline using mcpp fetch --to / --from + mcpp pack --offline --locked.
# Usage:
#   ./scripts/release-offline-bundle.sh [--dry-run] [--bundle-dir <dir>] [--out-dir <dir>] [--profile <feat>] [--version <v>]

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUNDLE_DIR="$ROOT/target/offline-bundle"
OUT_DIR="$ROOT/target/release-packages"
PROFILE="profile-linux-uring"
VERSION="0.1.0"
DRY_RUN=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --bundle-dir) BUNDLE_DIR="${2:?--bundle-dir requires path}"; shift 2 ;;
        --out-dir) OUT_DIR="${2:?--out-dir requires path}"; shift 2 ;;
        --profile) PROFILE="${2:?--profile requires feature}"; shift 2 ;;
        --version) VERSION="${2:?--version requires version}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help)
            sed -n '3,7p' "$0"
            exit 0
            ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

LOCK_FILE="$ROOT/mcpp/epoll/mcpp.lock"
EXPECTED_LOCK_SHA="91580f265b74fafc8fe626e128401535fc0a61e8a70757f3264b2e14757d06ac"
ACTUAL_LOCK_SHA="$(sha256sum "$LOCK_FILE" | awk '{print $1}')"
if [ "$ACTUAL_LOCK_SHA" != "$EXPECTED_LOCK_SHA" ]; then
    echo "error: lockfile digest mismatch before offline release: $ACTUAL_LOCK_SHA" >&2
    exit 1
fi

ARCH="$(uname -m)"
if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] lock_sha256=$ACTUAL_LOCK_SHA"
    echo "[dry-run] step 1: mcpp fetch --locked --features $PROFILE --to $BUNDLE_DIR"
    echo "[dry-run] step 2: mcpp fetch --from $BUNDLE_DIR --locked --features $PROFILE"
    echo "[dry-run] step 3: mcpp pack --offline --locked --features $PROFILE --pkg-format dir"
    echo "[dry-run] step 4: sha256sum bundle -> $OUT_DIR/nexus-${VERSION}-${ARCH}-${PROFILE}.tar.gz"
    exit 0
fi

mkdir -p "$BUNDLE_DIR" "$OUT_DIR"
(cd "$ROOT" && mcpp fetch --locked --features "$PROFILE" --to "$BUNDLE_DIR")
(cd "$ROOT" && mcpp fetch --from "$BUNDLE_DIR" --locked --features "$PROFILE")
(cd "$ROOT" && mcpp pack --offline --locked --features "$PROFILE" --pkg-format dir)

PACK_ROOT="$ROOT/target"
STAGED_DIR="$(find "$PACK_ROOT" -maxdepth 4 -type d -name "nexus*" | head -n 1)"
ARCHIVE="$OUT_DIR/nexus-${VERSION}-${ARCH}-${PROFILE}.tar.gz"
if [ -n "$STAGED_DIR" ]; then
    tar -C "$(dirname "$STAGED_DIR")" -czf "$ARCHIVE" "$(basename "$STAGED_DIR")"
    (cd "$OUT_DIR" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
    echo "Offline release packaged: $ARCHIVE"
fi
