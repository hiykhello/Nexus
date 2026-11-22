#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 5 && $# != 6 ]]; then
    echo "usage: $0 binary-dir seconds requests-per-second proxy-cpu-list harness-cpu-list [forward|reverse]" >&2
    exit 2
fi
binary_dir=$(realpath "$1")
seconds=$2
rate=$3
proxy_cpus=$4
harness_cpus=$5
order=${6:-forward}
if [[ $order == forward ]]; then
    modes=(per-worker shared snapshot)
    if [[ ${NEXUS_DNS_BENCH_GROUP:-0} == 1 ]]; then modes+=(group); fi
    scenarios=(hot uniform miss expiry)
elif [[ $order == reverse ]]; then
    modes=(snapshot shared per-worker)
    if [[ ${NEXUS_DNS_BENCH_GROUP:-0} == 1 ]]; then modes=(group "${modes[@]}"); fi
    scenarios=(expiry miss uniform hot)
else
    echo "order must be forward or reverse" >&2
    exit 2
fi
script_dir=$(cd "$(dirname "$0")" && pwd)
extra=()
if [[ ${NEXUS_DNS_BENCH_DIAGNOSTICS:-0} == 1 ]]; then
    extra+=(--diagnostics)
fi
for scenario in "${scenarios[@]}"; do
    for mode in "${modes[@]}"; do
        arguments=("$binary_dir/nexus-proxy-dns-bench-$mode" "$mode" "$scenario"
            --seconds "$seconds" --rate "$rate" --burst 8 --warm-rounds 32
            --proxy-cpus "$proxy_cpus" --harness-cpus "$harness_cpus" "${extra[@]}")
        if [[ ${NEXUS_DNS_BENCH_NETNS:-0} == 1 ]]; then
            unshare --user --map-root-user --net bash "$script_dir/proxy_bench_netns.sh" "${arguments[@]}"
        else
            python3 "$script_dir/proxy_bench.py" "${arguments[@]}"
        fi
    done
done
