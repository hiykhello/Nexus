#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "[nexus] Android ARM64 build helper"
if ! command -v java >/dev/null 2>&1; then
    echo "error: JDK 21 not found. Install Temurin JDK 21 or use GitHub Actions (.github/workflows/ci-cross-platform.yml)." >&2
    exit 1
fi
if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ]; then
    echo "error: ANDROID_HOME / ANDROID_SDK_ROOT not set." >&2
    exit 1
fi

if [ -n "${NEXUS_ANDROID_CORE_BIN:-}" ] && [ -f "$NEXUS_ANDROID_CORE_BIN" ]; then
    JNI_DIR="$ROOT/android/app/src/main/jniLibs/arm64-v8a"
    mkdir -p "$JNI_DIR"
    cp "$NEXUS_ANDROID_CORE_BIN" "$JNI_DIR/libnexus.so"
    echo "[nexus] Staged native core into $JNI_DIR/libnexus.so"
fi

cd "$ROOT/android"
if [ -x ./gradlew ]; then
    ./gradlew :core-bridge:testDebugUnitTest :app:assembleDebug --no-daemon
else
    gradle :core-bridge:testDebugUnitTest :app:assembleDebug --no-daemon
fi
