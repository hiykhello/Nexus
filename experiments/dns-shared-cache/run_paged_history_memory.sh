#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -x $1 ]]; then
    echo "usage: $0 /path/to/nexus-dns-paged-history-memory-bench" >&2
    exit 2
fi
binary=$(realpath "$1")
echo 'run,mode,readers,entries,warm_allocated_bytes,history_allocated_bytes,released_allocated_bytes,warm_rss_bytes,history_rss_bytes,released_rss_bytes'
for run in 1 2 3; do
    if [[ $run == 2 ]]; then modes=(paged ordered512); else modes=(ordered512 paged); fi
    for readers in 4 8 16; do
        for mode in "${modes[@]}"; do
            printf '%s,' "$run"
            "$binary" "$mode" "$readers"
        done
    done
done
