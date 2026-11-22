#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${NEXUS_DESKTOP_BUILD_DIR:-$ROOT/target/desktop-build}"
BUILD_UI="${NEXUS_DESKTOP_BUILD_UI:-OFF}"

cmake -S "$ROOT/desktop" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DNEXUS_DESKTOP_BUILD_UI="$BUILD_UI" \
    -DNEXUS_DESKTOP_BUILD_TESTS=ON
cmake --build "$BUILD_DIR" --parallel

if [ -n "${NEXUS_CORE_BIN:-}" ]; then
    echo "[nexus] Running live Desktop C++26 CTest against $NEXUS_CORE_BIN"
    NEXUS_CORE_BIN="$NEXUS_CORE_BIN" ctest --test-dir "$BUILD_DIR" --output-on-failure -V
else
    ctest --test-dir "$BUILD_DIR" --output-on-failure -V
fi
