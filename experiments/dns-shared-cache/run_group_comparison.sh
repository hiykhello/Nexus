#!/usr/bin/env bash
set -euo pipefail
if [[ ( $# != 3 && $# != 4 ) || ! -x $1 ]]; then
    echo "usage: $0 binary seconds reader-and-writer-cpu-list [forward|reverse]" >&2
    exit 2
fi
binary=$(realpath "$1")
seconds=$2
cpus=$3
order=${4:-forward}
group_count=${NEXUS_GROUP_COUNT:-2}
if [[ $group_count -gt 2 && ${NEXUS_GROUP_PAGED:-0} == 1 ]]; then
    echo "paged positive-only mode supports at most two groups" >&2
    exit 2
fi
if [[ $order == forward ]]; then
    modes=(per-inbound)
    if [[ $group_count -le 2 ]]; then modes+=(global); fi
    if [[ ${NEXUS_GROUP_PAGED:-0} == 1 ]]; then modes+=(paged); fi
    if [[ ${NEXUS_GROUP_SEMANTIC:-0} == 1 ]]; then modes+=(paged-semantic); fi
    if [[ ${NEXUS_GROUP_MEMBERSHIP:-0} == 1 ]]; then modes+=(group); fi
    distributions=(hot uniform)
    overlaps=(overlap disjoint)
    rates=(1000 10000)
elif [[ $order == reverse ]]; then
    modes=(per-inbound)
    if [[ $group_count -le 2 ]]; then modes=(global "${modes[@]}"); fi
    if [[ ${NEXUS_GROUP_PAGED:-0} == 1 ]]; then modes=(paged "${modes[@]}"); fi
    if [[ ${NEXUS_GROUP_SEMANTIC:-0} == 1 ]]; then modes=(paged-semantic "${modes[@]}"); fi
    if [[ ${NEXUS_GROUP_MEMBERSHIP:-0} == 1 ]]; then modes=(group "${modes[@]}"); fi
    distributions=(uniform hot)
    overlaps=(disjoint overlap)
    rates=(10000 1000)
else
    echo "order must be forward or reverse" >&2
    exit 2
fi
echo 'mode,distribution,overlap,readers,reads_per_reader_second,writes_per_second,seconds,reads_offered,reads_completed,reads_skipped,read_p50_ns,read_p99_ns,read_p999_ns,read_start_lag_p99_ns,writes_offered,writes_completed,writes_skipped,write_p50_ns,write_p99_ns,write_p999_ns,write_start_lag_p99_ns,warm_rss_kib,peak_rss_kib,read_hits,checksum,groups'
for rate in "${rates[@]}"; do
    for distribution in "${distributions[@]}"; do
        for overlap in "${overlaps[@]}"; do
            for mode in "${modes[@]}"; do
                "$binary" "$mode" "$distribution" "$overlap" "${NEXUS_GROUP_READERS:-8}" "${NEXUS_GROUP_READ_RATE:-50000}" "$rate" "$seconds" "$cpus" "$group_count"
            done
        done
    done
done
