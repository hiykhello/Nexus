#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ! -x $1 || ! -x $2 ]]; then
    echo "usage: $0 /path/to/baseline-fixture /path/to/shared-capacity-fixture" >&2
    exit 2
fi
baseline=$(realpath "$1")
grouped=$(realpath "$2")
experiment_dir=$(cd "$(dirname "$0")" && pwd)
rate=${DNS_BENCH_RATE_PER_GROUP:-60}
seconds=${DNS_BENCH_SECONDS:-3}
rounds=${DNS_BENCH_ROUNDS:-3}
for ((run=1;run<=rounds;++run)); do
    if (( run % 2 == 0 )); then modes=(group baseline); else modes=(baseline group); fi
    for scenario in 1-disjoint 2-overlap 2-disjoint; do
        groups=${scenario%-*}
        layout=${scenario#*-}
        for mode in "${modes[@]}"; do
            if [[ $mode == baseline ]]; then fixture=$baseline; else fixture=$grouped; fi
            python3 "$experiment_dir/proxy_shared_capacity_bench.py" "$fixture" --mode "$mode" \
                --groups "$groups" --layout "$layout" --run "$run" \
                --rate-per-group "$rate" --seconds "$seconds"
        done
    done
done
