#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ( $2 != forward && $2 != reverse ) ]]; then
    echo "usage: $0 path-to-cache-read-bench forward|reverse" >&2
    exit 2
fi
bench=$1
modes=(per-worker snapshot ordered module)
distributions=(uniform miss collision collision-miss prefix prefix-miss)
if [[ $2 == reverse ]]; then
    modes=(module ordered snapshot per-worker)
    distributions=(prefix-miss prefix collision-miss collision miss uniform)
fi
echo 'mode,threads,distribution,operations_per_second,p50_ns,p99_ns,p999_ns,checksum'
for distribution in "${distributions[@]}"; do
    for mode in "${modes[@]}"; do
        "$bench" "$mode" 8 "$distribution"
    done
done
