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
"${CXX:-g++}" -std=c++20 -O3 -pthread -DDNS_HP_XENIUM -I "$checkout" "$experiment_dir/hp_table_bench.cpp" -o "$binary"
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
