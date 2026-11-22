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
"${CXX:-g++}" -std=c++20 -O3 -pthread -I "$checkout" "$experiment_dir/hp_table_bench.cpp" "$checkout/mm_hp.cpp" -o "$binary"
echo 'mode,threads,distribution,load,read_per_second,read_p50_ns,read_p99_ns,read_p999_ns,write_p99_ns,write_p999_ns,write_time_over_read_time,live_nodes,peak_nodes,checksum'
for threads in 1 4 8; do
    for distribution in hot uniform; do
        for mode in local mutex hazard; do
            "$binary" "$mode" "$threads" "$distribution" read
        done
        for mode in mutex hazard; do
            "$binary" "$mode" "$threads" "$distribution" update
        done
    done
done
