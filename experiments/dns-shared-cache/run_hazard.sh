#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "usage: $0 /path/to/xenium-checkout" >&2
    exit 2
fi
xenium_dir=$(realpath "$1")
expected_revision=1c449ae953ce2a440b0d16c5ed1181d2754860ab
if [[ $(git -C "$xenium_dir" rev-parse HEAD) != "$expected_revision" ]] ||
   [[ -n $(git -C "$xenium_dir" status --porcelain --untracked-files=no) ]]; then
    echo "xenium checkout must be clean at $expected_revision" >&2
    exit 2
fi
experiment_dir=$(cd "$(dirname "$0")" && pwd)
binary=$(mktemp)
trap 'rm -f "$binary"' EXIT
"${CXX:-g++}" -std=c++20 -O2 -pthread -I "$xenium_dir" "$experiment_dir/hazard_reclaim.cpp" -o "$binary"
"$binary"
