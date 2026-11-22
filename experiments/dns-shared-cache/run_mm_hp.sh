#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "usage: $0 /path/to/mm_hp-checkout" >&2
    exit 2
fi
checkout=$(realpath "$1")
revision=b26e5edc779bf2afaea821549c04bf0a07b20f11
if [[ $(git -C "$checkout" rev-parse HEAD) != "$revision" ]] ||
   [[ -n $(git -C "$checkout" status --porcelain --untracked-files=no) ]]; then
    echo "mm_hp checkout must be clean at $revision" >&2
    exit 2
fi
experiment_dir=$(cd "$(dirname "$0")" && pwd)
binary=$(mktemp)
trap 'rm -f "$binary"' EXIT
"${CXX:-g++}" -std=c++20 -O2 -pthread -I "$checkout" "$experiment_dir/mm_hp_reclaim.cpp" "$checkout/mm_hp.cpp" -o "$binary"
"$binary"
