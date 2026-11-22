#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -x $1 ]]; then
    echo "usage: $0 /path/to/nexus-dns-group-history-memory-bench" >&2
    exit 2
fi
binary=$(realpath "$1")
echo 'run,layout,readers,budget_bytes,disabled,writes_before_stop,pinned_nodes,warm_charged_bytes,pinned_charged_bytes,peak_charged_bytes,recovered_charged_bytes,warm_allocated_delta_bytes,pinned_allocated_delta_bytes,recovered_allocated_delta_bytes,warm_rss_delta_bytes,pinned_rss_delta_bytes,recovered_rss_delta_bytes'
for run in 1 2 3; do
    if [[ $run == 2 ]]; then layouts=(disjoint overlap); else layouts=(overlap disjoint); fi
    for readers in 1 4; do
        for budget in 4194304 33554432; do
            for layout in "${layouts[@]}"; do
                printf '%s,' "$run"
                "$binary" "$layout" "$readers" "$budget"
            done
        done
    done
done
