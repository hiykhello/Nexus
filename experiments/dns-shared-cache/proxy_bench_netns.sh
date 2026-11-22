#!/usr/bin/env bash
set -euo pipefail
# The namespace exists only for this scenario; no host network settings change.
ip link set lo up
script_dir=$(cd "$(dirname "$0")" && pwd)
exec python3 "$script_dir/proxy_bench.py" "$@"
