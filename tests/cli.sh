#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
    printf 'usage: %s /path/to/nexus\n' "$0" >&2
    exit 2
fi
binary=$(realpath "$1")
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
expect_status() {
    local expected=$1
    shift
    local actual=0
    "$@" >"$temporary/out" 2>"$temporary/err" || actual=$?
    if [[ $actual != "$expected" ]]; then
        printf 'expected exit %s, got %s: %s\n' "$expected" "$actual" "$*" >&2
        cat "$temporary/err" >&2
        exit 1
    fi
}
expect_status 0 "$binary" --help
rg -q '^  run$' "$temporary/out"
rg -q '^  rule$' "$temporary/out"
expect_status 0 "$binary" rule --help
rg -q '^  convert$' "$temporary/out"
expect_status 0 "$binary" run --help
rg -q '^usage: nexus run ' "$temporary/out"
expect_status 0 "$binary" rule convert --help
rg -q '^usage: nexus rule convert ' "$temporary/out"
expect_status 2 "$binary"
expect_status 2 "$binary" rule
expect_status 2 "$binary" unknown
expect_status 2 "$binary" rule unknown
expect_status 2 "$binary" run --help extra
expect_status 2 "$binary" rule convert --help extra
expect_status 2 "$binary" rule convert kdl kdl input output
printf 'CLI help, dispatch and errors passed\n'
