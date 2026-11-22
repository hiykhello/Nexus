#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -x $1 ]]; then
    echo "usage: $0 /path/to/nexus-dns-group-pending-memory-bench" >&2
    exit 2
fi
binary=$(realpath "$1")
echo 'run,name_kind,readers,pending,snapshot_charged_bytes,full_allocated_delta_bytes,full_rss_delta_bytes,full_hwm_delta_bytes,cleared_allocated_delta_bytes,cleared_rss_delta_bytes,cleared_hwm_delta_bytes'
for run in 1 2 3; do
    if [[ $run == 2 ]]; then names=(long short); else names=(short long); fi
    for readers in 1 257; do
        for count in 0 128 4096; do
            for name in "${names[@]}"; do
                printf '%s,' "$run"
                "$binary" "$name" "$readers" "$count"
            done
        done
    done
done
