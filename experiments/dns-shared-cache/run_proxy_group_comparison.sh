#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 6 && $# != 7 ]]; then
    echo "usage: $0 binary-dir seconds requests-per-second proxy-cpus harness-cpus singbox-cpus [forward|reverse]" >&2
    exit 2
fi
binary_dir=$(realpath "$1")
seconds=$2
rate=$3
proxy_cpus=$4
harness_cpus=$5
singbox_cpus=$6
order=${7:-forward}
if [[ $order == forward ]]; then
    modes=(shared group)
    scenarios=(hot uniform disjoint expiry)
elif [[ $order == reverse ]]; then
    modes=(group shared)
    scenarios=(expiry disjoint uniform hot)
else
    echo "order must be forward or reverse" >&2
    exit 2
fi
script_dir=$(cd "$(dirname "$0")" && pwd)
for scenario in "${scenarios[@]}"; do
    for mode in "${modes[@]}"; do
        unshare --user --map-root-user --net bash "$script_dir/proxy_group_bench_netns.sh" \
            "$binary_dir/nexus-proxy-dns-group-bench-$mode" "$mode" "$scenario" \
            --seconds "$seconds" --rate "$rate" --proxy-cpus "$proxy_cpus" \
            --harness-cpus "$harness_cpus" --singbox-cpus "$singbox_cpus"
    done
done
