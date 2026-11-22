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
"${CXX:-g++}" -std=c++20 -O2 -pthread -DDNS_HP_XENIUM -I "$checkout" "$experiment_dir/hp_table_test.cpp" -o "$binary"
"$binary"
