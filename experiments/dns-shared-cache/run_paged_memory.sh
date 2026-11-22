#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -x $1 ]]; then
    echo "usage: $0 /path/to/nexus-dns-cache-memory-bench" >&2
    exit 2
fi
binary=$(realpath "$1")
echo 'run,mode,readers,entries,glibc_allocated_and_mapped_bytes,rss_delta_bytes'
for run in 1 2 3; do
    if [[ $run == 2 ]]; then modes=(paged ordered512); else modes=(ordered512 paged); fi
    for readers in 8 257; do
        for entries in 0 256 512; do
            for mode in "${modes[@]}"; do
                printf '%s,' "$run"
                "$binary" "$mode" "$readers" "$entries"
            done
        done
    done
done
