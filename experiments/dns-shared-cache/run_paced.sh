#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -x $1 ]]; then
    echo "usage: $0 /path/to/nexus-dns-cache-mixed-bench" >&2
    exit 2
fi
binary=$(realpath "$1")
echo 'mode,threads,distribution,target_writes_per_second,read_per_second,read_p50_ns,read_p99_ns,read_p999_ns,write_p99_ns,write_p999_ns,write_time_over_read_time,write_per_second,write_count,checksum'
for rate in 1000 10000 100000; do
    for distribution in hot uniform; do
        for mode in shared snapshot; do
            "$binary" "$mode" 8 "$distribution" "$rate" | awk -F, -v OFS=, -v rate="$rate" '{ print $1,$2,$3,rate,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13 }'
        done
    done
done
