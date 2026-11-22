#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ! -x $1 || ! -x $2 ]]; then
    echo "usage: $0 /path/to/fixed-churn /path/to/shared-churn" >&2
    exit 2
fi
fixed=$(realpath "$1")
shared=$(realpath "$2")
cpu=${DNS_CHURN_CPU:-0}
iterations=${DNS_CHURN_ITERATIONS:-20000}
echo 'run,variant,groups,entries_per_group,iterations,total_ns,p50_ns,p99_ns,p999_ns,charged_bytes,peak_charged_bytes'
for run in 1 2 3; do
    if (( run % 2 == 0 )); then variants=(shared fixed); else variants=(fixed shared); fi
    for groups in 1 2 17; do
        for entries in 256 1024; do
            if (( groups * entries > 8192 )); then continue; fi
            for variant in "${variants[@]}"; do
                if [[ $variant == shared ]]; then binary=$shared; else binary=$fixed; fi
                printf '%s,' "$run"
                taskset -c "$cpu" "$binary" "$groups" "$entries" "$iterations"
            done
        done
    done
done
