#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "usage: $0 /path/to/mm_hp-checkout" >&2
    exit 2
fi
checkout=$(realpath "$1")
revision=b26e5edc779bf2afaea821549c04bf0a07b20f11
if [[ $(git -C "$checkout" rev-parse HEAD) != "$revision" ]] ||
   [[ -n $(git -C "$checkout" status --porcelain --untracked-files=no) ]]; then
    echo "mm_hp checkout must be clean at $revision" >&2
    exit 2
fi
experiment_dir=$(cd "$(dirname "$0")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/tuned"
cp "$checkout/mm_hp.cpp" "$checkout/mm_hp.hpp" "$checkout/asymmetric_fence.hpp" "$scratch/tuned/"
python3 - "$scratch/tuned/mm_hp.cpp" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
before, after = 'k_reclaim_floor = 1000', 'k_reclaim_floor = 128'
if text.count(before) != 1:
    raise SystemExit('unexpected mm_hp source')
path.write_text(text.replace(before, after))
PY
"${CXX:-g++}" -std=c++20 -O3 -pthread -I "$checkout" "$experiment_dir/hp_table_bench.cpp" "$checkout/mm_hp.cpp" -o "$scratch/default"
"${CXX:-g++}" -std=c++20 -O3 -pthread -I "$scratch/tuned" "$experiment_dir/hp_table_bench.cpp" "$scratch/tuned/mm_hp.cpp" -o "$scratch/tuned-bin"
echo 'version,mode,threads,distribution,load,read_per_second,read_p50_ns,read_p99_ns,read_p999_ns,write_p99_ns,write_p999_ns,write_time_over_read_time,live_nodes,peak_nodes,checksum'
for repetition in 1 2 3; do
    for distribution in hot uniform; do
        for version in default tuned; do
            if [[ $version == default ]]; then binary="$scratch/default"; else binary="$scratch/tuned-bin"; fi
            printf '%s,' "$version"
            "$binary" hazard 8 "$distribution" update
        done
    done
done
