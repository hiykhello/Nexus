#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -x $1 ]]; then
    echo "usage: $0 /path/to/nexus-dns-cache-read-bench" >&2
    exit 2
fi
binary=$(realpath "$1")
echo 'mode,threads,distribution,operations_per_second,p50_ns,p99_ns,p999_ns,checksum'
for threads in 1 4 8; do
    for distribution in hot uniform; do
        for mode in per-worker sharded shared; do
            "$binary" "$mode" "$threads" "$distribution"
        done
    done
done
