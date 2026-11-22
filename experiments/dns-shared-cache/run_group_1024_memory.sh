#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ! -x $1 || ! -x $2 ]]; then
    echo "usage: $0 /path/to/256-group-memory /path/to/1024-group-memory" >&2
    exit 2
fi
small=$(realpath "$1")
large=$(realpath "$2")
echo 'run,mode,layout,readers_per_group,total_readers,entries_per_group,total_memberships,group_nodes,group_charged_bytes,glibc_allocated_and_mapped_delta_bytes,rss_delta_bytes,groups,capacity_per_group'
for run in 1 2 3; do
    if [[ $run == 2 ]]; then variants=(1024 256); else variants=(256 1024); fi
    for groups in 1 2 17; do
        if [[ $groups == 17 ]]; then readers=33; else readers=$((groups*2)); fi
        for capacity in "${variants[@]}"; do
            if [[ $capacity == 1024 ]]; then binary=$large; entries_list=(0 256 1024); else binary=$small; entries_list=(0 256); fi
            for entries in "${entries_list[@]}"; do
                if [[ $groups == 1 || $entries == 0 ]]; then layouts=(disjoint); else layouts=(disjoint overlap); fi
                for layout in "${layouts[@]}"; do
                    printf '%s,' "$run"
                    "$binary" group "$layout" 2 "$entries" "$groups" "$readers"
                done
            done
        done
    done
done
