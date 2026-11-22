#!/usr/bin/env bash
# Called inside a fresh user/network namespace for one diagnostic run.
set -euo pipefail
if [[ $# -lt 6 ]]; then
    echo "usage: $0 capture-binary capture-output capture-cpu fixture mode scenario [options...]" >&2
    exit 2
fi
capture=$1
output=$2
cpu=$3
shift 3
ip link set lo up
script_dir=$(cd "$(dirname "$0")" && pwd)
ready_dir=$(mktemp -d "${TMPDIR:-/tmp}/nexus-capture-ready.XXXXXXXX")
ready_fifo=$ready_dir/ready
mkfifo "$ready_fifo"
taskset -c "$cpu" "$capture" "$output" > "$ready_fifo" &
capture_pid=$!
cleanup() {
    kill -TERM "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" || true
    rm -rf "$ready_dir"
}
trap cleanup EXIT
if ! IFS= read -r -t 10 ready < "$ready_fifo" || [[ $ready != ready ]]; then
    echo "packet capture failed to start" >&2
    exit 2
fi
python3 "$script_dir/proxy_group_bench.py" "$@" --trace-udp
kill -TERM "$capture_pid"
wait "$capture_pid"
trap - EXIT
rm -rf "$ready_dir"
