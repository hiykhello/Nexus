#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v swift >/dev/null 2>&1; then
    echo "error: Swift 6 toolchain not found. Run on macOS 15+ or use GitHub Actions (.github/workflows/ci-cross-platform.yml)." >&2
    exit 1
fi

cd "$ROOT/apple"
swift --version
swift test --parallel
swift build -c release
