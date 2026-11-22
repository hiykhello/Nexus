#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -x $1 ]]; then
    echo "usage: $0 /path/to/nexus-dns-cache-mixed-bench" >&2
    exit 2
fi
binary=$(realpath "$1")
echo 'mode,threads,distribution,read_per_second,read_p50_ns,read_p99_ns,read_p999_ns,write_p99_ns,write_p999_ns,write_time_over_read_time,write_per_second,write_count,checksum'
for threads in 1 4 8 16; do
    for distribution in hot uniform; do
        for mode in shared semantic snapshot; do
            "$binary" "$mode" "$threads" "$distribution"
        done
    done
done
