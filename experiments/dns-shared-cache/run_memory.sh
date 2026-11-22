#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -x $1 ]]; then
    echo "usage: $0 /path/to/nexus-dns-cache-memory-bench" >&2
    exit 2
fi
binary=$(realpath "$1")
echo 'mode,workers,entries,glibc_allocated_and_mapped_bytes,rss_delta_bytes'
for workers in 1 4 8 16; do
    for mode in per-worker shared bounded semantic snapshot ordered module; do
        "$binary" "$mode" "$workers"
    done
done
