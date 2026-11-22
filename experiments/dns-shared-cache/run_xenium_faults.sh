#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "usage: $0 /path/to/xenium-checkout" >&2
    exit 2
fi
checkout=$(realpath "$1")
revision=1c449ae953ce2a440b0d16c5ed1181d2754860ab
if [[ $(git -C "$checkout" rev-parse HEAD) != "$revision" ]] ||
   [[ -n $(git -C "$checkout" status --porcelain --untracked-files=no) ]]; then
    echo "xenium checkout must be clean at $revision" >&2
    exit 2
fi
experiment_dir=$(cd "$(dirname "$0")" && pwd)
binary=$(mktemp)
trap 'rm -f "$binary"' EXIT
"${CXX:-g++}" -std=c++20 -O1 -g -fsanitize=undefined -fno-sanitize-recover=undefined -pthread -I "$checkout" "$experiment_dir/xenium_empty_guard.cpp" -o "$binary"
set +e
"$binary"
guard_status=$?
set -e
if [[ $guard_status != 1 ]]; then echo "unexpected empty guard status: $guard_status" >&2; exit 1; fi
"${CXX:-g++}" -std=c++20 -O1 -pthread -I "$checkout" "$experiment_dir/xenium_scan_allocation.cpp" -o "$binary"
set +e
"$binary"
scan_status=$?
set -e
if [[ $scan_status != 42 ]]; then echo "unexpected scan failure status: $scan_status" >&2; exit 1; fi
echo 'empty guard triggers UBSan; forced scan allocation failure invokes terminate'
