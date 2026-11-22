#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 3 || ! -x $1 || ! -x $2 || ! -x $3 ]]; then
    echo "usage: $0 /path/to/256-memory /path/to/1024-memory /path/to/shared-capacity-memory" >&2
    exit 2
fi
small=$(realpath "$1")
medium=$(realpath "$2")
shared=$(realpath "$3")
echo 'run,variant,mode,layout,readers_per_group,total_readers,entries_per_group,total_memberships,group_nodes,group_charged_bytes,glibc_allocated_and_mapped_delta_bytes,rss_delta_bytes,groups,configured_capacity'
for run in 1 2 3; do
    if [[ $run == 2 ]]; then variants=(shared 1024 256); else variants=(256 1024 shared); fi
    for groups in 1 2 17; do
        if [[ $groups == 17 ]]; then readers=33; else readers=$((groups*2)); fi
        for variant in "${variants[@]}"; do
            case "$variant" in
                256) binary=$small; entries_list=(0 256) ;;
                1024) binary=$medium; entries_list=(0 256); if [[ $groups != 17 ]]; then entries_list+=(1024); fi ;;
                shared)
                    binary=$shared; entries_list=(0 256)
                    if [[ $groups == 1 ]]; then entries_list+=(1024 4096); fi
                    if [[ $groups == 2 ]]; then entries_list+=(1024 2048); fi ;;
            esac
            for entries in "${entries_list[@]}"; do
                if [[ $groups == 1 || $entries == 0 ]]; then layouts=(disjoint); else layouts=(disjoint overlap); fi
                for layout in "${layouts[@]}"; do
                    printf '%s,%s,' "$run" "$variant"
                    if [[ $variant == shared ]]; then
                        "$binary" group "$layout" 2 "$entries" "$groups" "$readers" 4352
                    else
                        "$binary" group "$layout" 2 "$entries" "$groups" "$readers"
                    fi
                done
            done
        done
    done
done
