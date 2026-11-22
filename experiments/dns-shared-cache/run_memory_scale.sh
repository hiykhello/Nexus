#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -x $1 ]]; then
    echo "usage: $0 /path/to/nexus-dns-cache-memory-bench" >&2
    exit 2
fi
binary=$(realpath "$1")
echo 'mode,readers,entries,glibc_allocated_and_mapped_bytes,rss_delta_bytes'
for readers in 1 8 16 64 257; do
    for entries in 0 16 256; do
        for mode in per-worker snapshot ordered module; do
            "$binary" "$mode" "$readers" "$entries"
        done
    done
done
