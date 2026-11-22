#!/usr/bin/env bash
set -euo pipefail
if [[ ( $# != 3 && $# != 4 ) || ! -x $1 ]]; then
    echo "usage: $0 /path/to/nexus-dns-cache-offered-bench seconds reader-and-writer-cpu-list [forward|reverse]" >&2
    exit 2
fi
binary=$(realpath "$1")
seconds=$2
cpus=$3
order=${4:-forward}
if [[ $order == forward ]]; then
    modes=(per-worker shared snapshot ordered module)
elif [[ $order == reverse ]]; then
    modes=(module ordered snapshot shared per-worker)
else
    echo "order must be forward or reverse" >&2
    exit 2
fi
echo 'mode,readers,distribution,reads_per_reader_second,writes_per_second,seconds,reads_offered,reads_completed,reads_skipped,read_p50_ns,read_p99_ns,read_p999_ns,read_start_lag_p99_ns,read_start_lag_p999_ns,writes_offered,writes_completed,writes_skipped,write_p50_ns,write_p99_ns,write_p999_ns,write_start_lag_p99_ns,write_start_lag_p999_ns,checksum,read_hits,read_misses'
for rate in 1000 10000; do
    for mode in "${modes[@]}"; do
        "$binary" "$mode" 8 churn 50000 "$rate" "$seconds" "$cpus"
    done
done
