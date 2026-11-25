#!/usr/bin/env bash
set -euo pipefail

# Builds and verifies a 100% static Linux musl + mimalloc Nexus binary using
# mcpp/linux-musl-mimalloc/mcpp.toml inside an Alpine edge sysroot (or natively on Alpine).
#
# Usage:
#   ./scripts/build-linux-musl-mimalloc.sh [options]
#
# Options:
#   --arch <x86_64|aarch64>        Target architecture (must match host in --container mode)
#   --profile <release|size|speed> Build profile (default: release)
#   --features <list>              Optional extra features (e.g. io-uring)
#   --out <path>                   Output binary path (default: target/linux-musl-mimalloc/nexus)
#   --engine <auto|podman|docker>  Container engine for non-musl hosts (default: auto)
#   --image <ref>                  Alpine container image (default: docker.io/library/alpine:edge)
#   --native                       Build natively inside an Alpine musl environment
#   --offline                      Pass --offline to mcpp build (automatic in container mode)
#   --no-verify                    Skip static ELF / GNU_STACK / MIMALLOC_SHOW_STATS checks
#   --dry-run                      Print resolved build plan without compiling

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
_cleanup_dirs=()
cleanup_tmp_dirs() {
    if [ "${#_cleanup_dirs[@]}" -gt 0 ]; then
        rm -rf "${_cleanup_dirs[@]}"
    fi
}
trap cleanup_tmp_dirs EXIT

normalize_arch() {
    case "$1" in
        x86_64|amd64) printf '%s\n' "x86_64" ;;
        aarch64|arm64) printf '%s\n' "aarch64" ;;
        *) return 1 ;;
    esac
}

HOST_ARCH="$(normalize_arch "$(uname -m)")" || {
    echo "error: unsupported host architecture '$(uname -m)'" >&2
    exit 2
}
ARCH="$HOST_ARCH"
PROFILE="release"
FEATURES=""
OUT_BIN="$ROOT/target/linux-musl-mimalloc/nexus"
ENGINE="auto"
IMAGE="${NEXUS_ALPINE_IMAGE:-docker.io/library/alpine:edge}"
MODE="auto"
OFFLINE=0
VERIFY=1
DRY_RUN=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --arch) ARCH="${2:?--arch requires x86_64 or aarch64}"; shift 2 ;;
        --arch=*) ARCH="${1#*=}"; shift ;;
        --profile) PROFILE="${2:?--profile requires a name}"; shift 2 ;;
        --profile=*) PROFILE="${1#*=}"; shift ;;
        --features) FEATURES="${2:?--features requires a list}"; shift 2 ;;
        --features=*) FEATURES="${1#*=}"; shift ;;
        --out) OUT_BIN="${2:?--out requires a path}"; shift 2 ;;
        --out=*) OUT_BIN="${1#*=}"; shift ;;
        --engine) ENGINE="${2:?--engine requires auto|podman|docker}"; shift 2 ;;
        --engine=*) ENGINE="${1#*=}"; shift ;;
        --image) IMAGE="${2:?--image requires an image reference}"; shift 2 ;;
        --image=*) IMAGE="${1#*=}"; shift ;;
        --native) MODE="native"; shift ;;
        --container) MODE="container"; shift ;;
        --offline) OFFLINE=1; shift ;;
        --no-verify) VERIFY=0; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help)
            sed -n '4,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

ARCH="$(normalize_arch "$ARCH")" || {
    echo "error: unsupported --arch '$ARCH' (expected x86_64 or aarch64)" >&2
    exit 2
}
case "$ARCH" in
    x86_64) DOCKER_PLATFORM="linux/amd64" ;;
    aarch64) DOCKER_PLATFORM="linux/arm64" ;;
esac
case "$PROFILE" in
    release|size|speed) ;;
    *) echo "error: unsupported --profile '$PROFILE' (expected release, size, or speed)" >&2; exit 2 ;;
esac

if [ "$MODE" = "auto" ]; then
    if [ -f /etc/alpine-release ]; then
        MODE="native"
    else
        MODE="container"
    fi
fi

if [ "$MODE" = "container" ] && [ "$ARCH" != "$HOST_ARCH" ]; then
    echo "error: --container mode mounts the host-arch ($HOST_ARCH) mcpp/llvm@23.1.6 toolchain and cannot cross-build $ARCH." >&2
    echo "       Build ${ARCH}-linux-musl on a native $ARCH Linux host/runner, or with --native inside an $ARCH Alpine environment." >&2
    exit 2
fi

verify_binary() {
    local bin="$1"
    echo "==> Verifying static Linux musl + mimalloc binary: $bin"
    ls -lh "$bin"

    local file_out
    file_out="$(file "$bin")"
    echo "  file: $file_out"
    printf '%s\n' "$file_out" | grep -q 'statically linked' || {
        echo "FAIL: binary is not statically linked" >&2
        return 1
    }

    local phdrs
    phdrs="$(LC_ALL=C readelf -lW "$bin")"
    if printf '%s\n' "$phdrs" | grep -q 'INTERP'; then
        echo "FAIL: static binary must not contain PT_INTERP" >&2
        return 1
    fi
    printf '%s\n' "$phdrs" | grep -q 'GNU_RELRO' || {
        echo "FAIL: binary missing GNU_RELRO" >&2
        return 1
    }
    local stack_line stack_memsiz stack_flg
    stack_line="$(printf '%s\n' "$phdrs" | awk '$1 == "GNU_STACK" { print; exit }')"
    [ -n "$stack_line" ] || { echo "FAIL: missing GNU_STACK header" >&2; return 1; }
    stack_memsiz="$(printf '%s\n' "$stack_line" | awk '{ print $6 }')"
    stack_flg="$(printf '%s\n' "$stack_line" | awk '{ print $7 }')"
    echo "  GNU_STACK: MemSiz=$stack_memsiz Flg=$stack_flg"
    if [ "$stack_flg" != "RW" ]; then
        echo "FAIL: GNU_STACK must be non-executable (RW), got '$stack_flg'" >&2
        return 1
    fi
    if [ "$((stack_memsiz))" -lt 2097152 ]; then
        echo "FAIL: GNU_STACK MemSiz ($stack_memsiz) < 0x200000 (2 MiB)" >&2
        return 1
    fi

    if [ "$ARCH" = "$HOST_ARCH" ]; then
        local help_out
        help_out="$(MIMALLOC_SHOW_STATS=1 "$bin" --help 2>&1)"
        printf '%s\n' "$help_out" | grep -q 'usage: nexus' || {
            echo "FAIL: --help output missing usage banner" >&2
            return 1
        }
        printf '%s\n' "$help_out" | grep -q 'arenas' || {
            echo "FAIL: MIMALLOC_SHOW_STATS=1 did not report mimalloc heap stats" >&2
            return 1
        }
        echo "  MIMALLOC_SHOW_STATS=1 --help: PASS (mimalloc stats confirmed)"

        local cfg="$ROOT/docs/configuration/examples/socks5.kdl"
        if [ -f "$cfg" ]; then
            "$bin" check --config "$cfg" | grep -q 'configuration valid' || {
                echo "FAIL: nexus check failed on $cfg" >&2
                return 1
            }
            echo "  nexus check socks5.kdl: PASS"
        fi
        "$bin" generate uuid >/dev/null
        echo "  nexus generate uuid: PASS"
    else
        echo "  (skipping live execution check for cross-arch $ARCH on $HOST_ARCH host)"
    fi
}

prepare_alpine_shadow_mcpp_home() {
    local orig_reg="$1"
    local shadow_home="$2"
    local sreg="$shadow_home/registry"
    local llvm_ver="23.1.6"
    local triple="${ARCH}-alpine-linux-musl"
    local gnu_triple="${ARCH}-unknown-linux-gnu"
    local ollvm="$orig_reg/data/xpkgs/xim-x-llvm/$llvm_ver"
    local sllvm="$sreg/data/xpkgs/xim-x-llvm/$llvm_ver"

    [ -d "$ollvm" ] || {
        echo "error: mcpp llvm@$llvm_ver payload not found at $ollvm" >&2
        return 1
    }

    rm -rf "$shadow_home"
    mkdir -p "$sllvm/bin" "$sllvm/include/c++" "$sllvm/lib/$gnu_triple" \
             "$sreg/data/runtimedir" "$sreg/data/roots" "$sreg/logs"

    local f bn p lib
    for f in abi abi.gen abi.json bin; do
        [ -e "$orig_reg/$f" ] && ln -s "$orig_reg/$f" "$sreg/$f"
    done
    for f in config subos .xlings .xlings-home .xlings.json; do
        [ -e "$orig_reg/$f" ] && cp -a "$orig_reg/$f" "$sreg/$f"
    done
    rm -f "$sreg/subos/.mcpp-state.lock" "$sreg/subos/.mcpp-state.lock.owner"
    # Copy (never symlink to :ro) mutable index/metadata dirs so mcpp/xlings never hits EROFS.
    for f in local-indexrepo xim-index-repos xim-pkgindex versions.json; do
        [ -e "$orig_reg/data/$f" ] && cp -a "$orig_reg/data/$f" "$sreg/data/$f"
    done
    [ -e "$orig_reg/data/roots/mcpp" ] && cp -a "$orig_reg/data/roots/mcpp" "$sreg/data/roots/mcpp"

    for p in "$orig_reg/data/xpkgs"/*; do
        [ -e "$p" ] || continue
        bn="$(basename "$p")"
        [ "$bn" = "xim-x-llvm" ] && continue
        ln -s "$p" "$sreg/data/xpkgs/$bn"
    done
    for f in "$ollvm"/* "$ollvm"/.x*; do
        [ -e "$f" ] || continue
        bn="$(basename "$f")"
        case "$bn" in bin|include|lib) continue ;; esac
        ln -s "$f" "$sllvm/$bn"
    done
    for f in "$ollvm/include"/*; do
        [ -e "$f" ] || continue
        bn="$(basename "$f")"
        [ "$bn" = "c++" ] && continue
        ln -s "$f" "$sllvm/include/$bn"
    done
    ln -s /usr/include/c++/v1 "$sllvm/include/c++/v1"
    for f in "$ollvm/lib"/*; do
        [ -e "$f" ] || continue
        bn="$(basename "$f")"
        [ "$bn" = "$gnu_triple" ] && continue
        ln -s "$f" "$sllvm/lib/$bn"
    done
    for f in "$ollvm/lib/$gnu_triple"/*; do
        [ -e "$f" ] || continue
        bn="$(basename "$f")"
        case "$bn" in libc++.a|libc++abi.a|libunwind.a) continue ;; esac
        ln -s "$f" "$sllvm/lib/$gnu_triple/$bn"
    done
    for lib in libc++.a libc++abi.a libunwind.a; do
        ln -s "/usr/lib/$lib" "$sllvm/lib/$gnu_triple/$lib"
    done
    for f in "$ollvm/bin"/*; do
        [ -e "$f" ] || continue
        bn="$(basename "$f")"
        case "$bn" in clang|clang++|clang-23|clang.cfg|clang++.cfg|clang-23.cfg) continue ;; esac
        ln -s "$f" "$sllvm/bin/$bn"
    done
    # Copy clang-23 binary so Clang's realpath(argv[0]) reads our Alpine musl clang*.cfg.
    cp -a "$ollvm/bin/clang-23" "$sllvm/bin/clang-23"
    ln -s clang-23 "$sllvm/bin/clang"
    ln -s clang-23 "$sllvm/bin/clang++"

    local builtin_lib resdir
    builtin_lib="$(find /usr -name 'libclang_rt.builtins*.a' | head -n 1)"
    if [ -z "$builtin_lib" ]; then
        echo "error: libclang_rt.builtins*.a not found under /usr (install Alpine compiler-rt)" >&2
        return 1
    fi
    resdir="$(dirname "$builtin_lib")/../.."
    cat > "$sllvm/bin/clang.cfg" <<EOF
--target=$triple
--sysroot=/
-resource-dir=$resdir
-fuse-ld=lld
--rtlib=compiler-rt
--unwindlib=libunwind
EOF
    cp "$sllvm/bin/clang.cfg" "$sllvm/bin/clang-23.cfg"
    cat > "$sllvm/bin/clang++.cfg" <<EOF
--target=$triple
--sysroot=/
-resource-dir=$resdir
-fuse-ld=lld
--rtlib=compiler-rt
--unwindlib=libunwind
-stdlib=libc++
EOF
}

bootstrap_host_mcpp_cache() {
    local host_home="$1"
    local mcpp_reg="$host_home/registry"
    local xpkg_cache="$host_home/musl-xpkgs"

    if [ ! -d "$mcpp_reg/data/xpkgs/xim-x-llvm/23.1.6" ] || [ ! -d "$mcpp_reg/data/xpkgs/xim-x-ninja" ]; then
        echo "==> Bootstrapping managed llvm@23.1.6 and ninja into $mcpp_reg..."
        local boot_dir
        boot_dir="$(mktemp -d "${TMPDIR:-/tmp}/nexus-mcpp-boot.XXXXXX")"
        _cleanup_dirs+=("$boot_dir")
        mkdir -p "$boot_dir/src"
        cat > "$boot_dir/mcpp.toml" <<'EOF'
[package]
name = "nexus-bootstrap"
version = "0.1.0"
standard = "c++26"
[toolchain]
default = "llvm@23.1.6"
[build]
sources = []
[targets.boot]
kind = "bin"
main = "src/main.c"
EOF
        printf 'int main(void) { return 0; }\n' > "$boot_dir/src/main.c"
        (cd "$boot_dir" && MCPP_HOME="$host_home" mcpp build --sysroot glibc@system boot >/dev/null)
        rm -rf "$boot_dir"
    fi

    local lock_stamp
    local expected_pkgs=(
        nexus-x-argon2-source nexus-x-beman-inplace-vector nexus-x-blake3-source
        nexus-x-boringssl-crypto-source nexus-x-capy-source nexus-x-corosio-source
        nexus-x-glaze-kdl nexus-x-mimalloc-source nexus-x-ngcpp-proxy
        nexus-x-nghttp2-source nexus-x-nghttp3-source nexus-x-ngtcp2-source
    )
    lock_stamp="$(sha256sum "$ROOT/mcpp/linux-musl-mimalloc/mcpp.lock" "$ROOT/3rdparty/mcpp-pins.json" | awk '{print $1}' | sha256sum | awk '{print $1}')"
    local missing=0 pkg
    if [ ! -f "$xpkg_cache/.lock-stamp" ] || [ "$(cat "$xpkg_cache/.lock-stamp")" != "$lock_stamp" ]; then
        missing=1
    else
        for pkg in "${expected_pkgs[@]}"; do
            if [ ! -d "$xpkg_cache/.mcpp/.xlings/data/xpkgs/$pkg" ]; then
                missing=1
                break
            fi
        done
    fi

    if [ "$missing" -eq 1 ]; then
        echo "==> Fetching pinned upstream source packages into $xpkg_cache..."
        local stage_dir
        stage_dir="$(mktemp -d "${TMPDIR:-/tmp}/nexus-musl-fetch.XXXXXX")"
        _cleanup_dirs+=("$stage_dir")
        tar -C "$ROOT" \
            --exclude='./target' --exclude='./mcpp/epoll/target' \
            --exclude='./mcpp/linux-musl-mimalloc/target' --exclude='./.git' \
            --exclude='./android' --exclude='./apple' --exclude='./desktop' \
            --exclude='./web' --exclude='./.mcpp' \
            -cf - . | tar -C "$stage_dir" -xf -
        local rdir="$stage_dir/mcpp/linux-musl-mimalloc/.mcpp/.xlings/data/runtimedir"
        mkdir -p "$rdir"
        if [ -d "$ROOT/.mcpp/.xlings/data/runtimedir" ]; then
            cp "$ROOT/.mcpp/.xlings/data/runtimedir"/*.tar.gz \
               "$ROOT/.mcpp/.xlings/data/runtimedir"/*.tar.xz "$rdir/" 2>/dev/null || true
        fi
        if [ -d "$xpkg_cache/.mcpp/.xlings/data/runtimedir" ]; then
            cp "$xpkg_cache/.mcpp/.xlings/data/runtimedir"/*.tar.gz \
               "$xpkg_cache/.mcpp/.xlings/data/runtimedir"/*.tar.xz "$rdir/" 2>/dev/null || true
        fi
        (
            cd "$stage_dir/mcpp/linux-musl-mimalloc"
            MCPP_HOME="$host_home" mcpp --locked fetch --profile "$PROFILE"
        )
        rm -rf "$xpkg_cache/.mcpp" "$xpkg_cache/.lock-stamp"
        mkdir -p "$xpkg_cache"
        cp -a "$stage_dir/mcpp/linux-musl-mimalloc/.mcpp" "$xpkg_cache/.mcpp"
        printf '%s\n' "$lock_stamp" > "$xpkg_cache/.lock-stamp"
        rm -rf "$stage_dir"
    fi
}

if [ "$DRY_RUN" -eq 1 ]; then
    echo "Nexus static Linux musl + mimalloc build plan:"
    echo "  mode:     $MODE"
    echo "  arch:     $ARCH ($DOCKER_PLATFORM)"
    echo "  profile:  $PROFILE"
    echo "  features: ${FEATURES:-<default 50/51 Linux epoll+srs+tailscale>}"
    echo "  manifest: $ROOT/mcpp/linux-musl-mimalloc/mcpp.toml"
    echo "  image:    $IMAGE"
    echo "  out:      $OUT_BIN"
    echo "  verify:   $VERIFY"
    exit 0
fi

if [ "$MODE" = "native" ]; then
    ORIG_REG="${MCPP_HOME:-$HOME/.mcpp}/registry"
    SHADOW_HOME="$(mktemp -d "${TMPDIR:-/tmp}/nexus-musl-mcpp.XXXXXX")"
    _cleanup_dirs+=("$SHADOW_HOME")
    BUILD_LOG="$SHADOW_HOME/mcpp-build.log"
    prepare_alpine_shadow_mcpp_home "$ORIG_REG" "$SHADOW_HOME"

    MCPP_FLAGS=(--locked)
    if [ "$OFFLINE" -eq 1 ]; then
        MCPP_FLAGS=(--offline "${MCPP_FLAGS[@]}")
    fi
    BUILD_ARGS=(build --profile "$PROFILE" --print-fingerprint --cache=off)
    if [ -n "$FEATURES" ]; then
        BUILD_ARGS+=(--features "$FEATURES")
    fi
    BUILD_ARGS+=(nexus)

    PKG_DIR="$ROOT/mcpp/linux-musl-mimalloc"
    (
        cd "$PKG_DIR"
        MCPP_HOME="$SHADOW_HOME" mcpp "${MCPP_FLAGS[@]}" "${BUILD_ARGS[@]}" 2>&1 | tee "$BUILD_LOG"
    )
    LINEAGE="$(awk '/^Lineage:[[:space:]]+/ { print $2; exit }' "$BUILD_LOG")"
    if [ -z "$LINEAGE" ]; then
        echo "error: failed to extract mcpp build lineage from $BUILD_LOG" >&2
        exit 1
    fi
    BUILT_BIN="$PKG_DIR/target/${ARCH}-linux-musl/$LINEAGE/bin/nexus"
    if [ ! -x "$BUILT_BIN" ]; then
        BUILT_BIN="$(find "$PKG_DIR/target" -path "*/$LINEAGE/bin/nexus" -type f -executable | head -n 1)"
    fi
    [ -x "$BUILT_BIN" ] || { echo "error: built nexus binary not found for lineage $LINEAGE" >&2; exit 1; }
    mkdir -p "$(dirname "$OUT_BIN")"
    install -m 0755 "$BUILT_BIN" "$OUT_BIN"
    if [ "$VERIFY" -eq 1 ]; then
        verify_binary "$OUT_BIN"
    fi
    exit 0
fi

# Containerized build on glibc Linux hosts (works with both podman and docker).
if [ "$ENGINE" = "auto" ]; then
    if command -v podman >/dev/null 2>&1; then
        ENGINE="podman"
    elif command -v docker >/dev/null 2>&1; then
        ENGINE="docker"
    else
        echo "error: neither podman nor docker found (or run natively on Alpine with --native)" >&2
        exit 1
    fi
fi

MCPP_OPT="${MCPP_OPT:-/opt/mcpp}"
HOST_MCPP_HOME="${MCPP_HOME:-$HOME/.mcpp}"
MCPP_REG="$HOST_MCPP_HOME/registry"
MUSL_XPKG_CACHE="$HOST_MCPP_HOME/musl-xpkgs"
if [ ! -x "$MCPP_OPT/bin/mcpp" ]; then
    echo "error: mcpp binary not found at $MCPP_OPT/bin/mcpp (set MCPP_OPT if installed elsewhere)" >&2
    exit 1
fi

bootstrap_host_mcpp_cache "$HOST_MCPP_HOME"

OUT_DIR_ABS="$(mkdir -p "$(dirname "$OUT_BIN")" && cd "$(dirname "$OUT_BIN")" && pwd)"
OUT_NAME="$(basename "$OUT_BIN")"

echo "==> Building static Linux $ARCH musl + mimalloc ($PROFILE) via $ENGINE ($IMAGE)..."
"$ENGINE" run --rm \
    --platform "$DOCKER_PLATFORM" \
    -v "$MCPP_REG:$MCPP_REG:ro" \
    -v "$MUSL_XPKG_CACHE:/musl-xpkgs:ro" \
    -v "$MCPP_OPT:/opt/mcpp:ro" \
    -v "$ROOT:/work:ro" \
    -v "$OUT_DIR_ABS:/out:rw" \
    -e HOME="$HOME" \
    -e MCPP_HOME="$HOST_MCPP_HOME" \
    -e MCPP_VENDORED_XLINGS=/opt/mcpp/registry/bin/xlings \
    -e PATH="/opt/mcpp/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    -e NEXUS_BUILD_ARCH="$ARCH" \
    -e NEXUS_BUILD_PROFILE="$PROFILE" \
    -e NEXUS_BUILD_FEATURES="$FEATURES" \
    -e NEXUS_OUT_NAME="$OUT_NAME" \
    "$IMAGE" sh -euxc '
apk add --no-cache \
    bash musl-dev linux-headers compiler-rt libc++-dev libc++-static \
    llvm-libunwind-dev llvm-libunwind-static liburing-dev zlib-dev zlib-static \
    file binutils git patch

mkdir -p /tmp/nexus-src
tar -C /work \
    --exclude="./target" \
    --exclude="./mcpp/epoll/target" \
    --exclude="./mcpp/linux-musl-mimalloc/target" \
    --exclude="./.git" \
    --exclude="./android" \
    --exclude="./apple" \
    --exclude="./desktop" \
    --exclude="./web" \
    --exclude="./.mcpp" \
    -cf - . | tar -C /tmp/nexus-src -xf -

cp -a /musl-xpkgs/.mcpp /tmp/nexus-src/mcpp/linux-musl-mimalloc/.mcpp

set -- --native --offline --arch "$NEXUS_BUILD_ARCH" --profile "$NEXUS_BUILD_PROFILE" --out "/out/$NEXUS_OUT_NAME" --no-verify
if [ -n "$NEXUS_BUILD_FEATURES" ]; then
    set -- "$@" --features "$NEXUS_BUILD_FEATURES"
fi
bash /tmp/nexus-src/scripts/build-linux-musl-mimalloc.sh "$@"
chmod 0755 "/out/$NEXUS_OUT_NAME"
'

if [ "$VERIFY" -eq 1 ]; then
    verify_binary "$OUT_DIR_ABS/$OUT_NAME"
fi
echo "==> Done: $OUT_DIR_ABS/$OUT_NAME"
