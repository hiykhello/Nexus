#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -x $1 ]]; then
    echo "usage: $0 /path/to/nexus-dns-group-memory-bench" >&2
    exit 2
fi
binary=$(realpath "$1")
echo 'run,mode,layout,readers_per_inbound,total_readers,entries_per_group,total_memberships,group_nodes,group_charged_bytes,glibc_allocated_and_mapped_delta_bytes,rss_delta_bytes'
for run in 1 2 3; do
    if [[ $run == 2 ]]; then modes=(group separate); else modes=(separate group); fi
    for readers in 1 4 16; do
        for entries in 0 256; do
            for layout in overlap disjoint; do
                for mode in "${modes[@]}"; do
                    printf '%s,' "$run"
                    "$binary" "$mode" "$layout" "$readers" "$entries"
                done
            done
        done
    done
done
