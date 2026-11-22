#!/usr/bin/env bash
set -euo pipefail
ip link set lo up
script_dir=$(cd "$(dirname "$0")" && pwd)
if [[ ${NEXUS_BENCH_LOCAL:-0} == 1 ]]; then
    mount --make-rprivate /
    bench_dir=$(mktemp -d)
    trap 'rm -rf "$bench_dir"' EXIT
    printf 'nameserver 127.0.0.1\noptions timeout:2 attempts:1\n' > "$bench_dir/resolv.conf"
    printf '127.0.0.1 localhost\n' > "$bench_dir/hosts"
    mount --bind "$bench_dir/resolv.conf" /etc/resolv.conf
    mount --bind "$bench_dir/hosts" /etc/hosts
    python3 "$script_dir/proxy_group_bench.py" "$@" --local-dns
else
    exec python3 "$script_dir/proxy_group_bench.py" "$@"
fi
