#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${NEXUS_DESKTOP_BUILD_DIR:-$ROOT/target/desktop-build}"
BUILD_UI="${NEXUS_DESKTOP_BUILD_UI:-OFF}"
SLINT_CMAKE_DIR="${SLINT_DIR:-}"

if [ "$BUILD_UI" = "ON" ] && [ -z "$SLINT_CMAKE_DIR" ] && [ -d "${HOME:-}/.local/opt/slint-cpp-1.19.0/lib/cmake/Slint" ]; then
    SLINT_CMAKE_DIR="${HOME}/.local/opt/slint-cpp-1.19.0/lib/cmake/Slint"
fi

CMAKE_ARGS=(
    -S "$ROOT/desktop"
    -B "$BUILD_DIR"
    -G Ninja
    -DCMAKE_BUILD_TYPE=Release
    -DNEXUS_DESKTOP_BUILD_UI="$BUILD_UI"
    -DNEXUS_DESKTOP_BUILD_TESTS=ON
)
if [ -n "$SLINT_CMAKE_DIR" ]; then
    CMAKE_ARGS+=(-DSlint_DIR="$SLINT_CMAKE_DIR")
fi

cmake "${CMAKE_ARGS[@]}"
cmake --build "$BUILD_DIR" --parallel

if [ -n "${NEXUS_CORE_BIN:-}" ]; then
    echo "[nexus] Running live Desktop C++26 CTest against $NEXUS_CORE_BIN"
    NEXUS_CORE_BIN="$NEXUS_CORE_BIN" ctest --test-dir "$BUILD_DIR" --output-on-failure -V
else
    ctest --test-dir "$BUILD_DIR" --output-on-failure -V
fi
