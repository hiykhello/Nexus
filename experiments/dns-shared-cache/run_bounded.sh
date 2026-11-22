#!/usr/bin/env bash
set -euo pipefail
experiment_dir=$(cd "$(dirname "$0")" && pwd)
test_binary=$(mktemp)
fault_binary=$(mktemp)
collision_binary=$(mktemp)
bench_binary=$(mktemp)
trap 'rm -f "$test_binary" "$fault_binary" "$collision_binary" "$bench_binary"' EXIT
"${CXX:-g++}" -std=c++20 -O3 -pthread -DDNS_HP_BOUNDED "$experiment_dir/hp_table_test.cpp" -o "$test_binary"
"$test_binary"
"${CXX:-g++}" -std=c++20 -O3 -pthread "$experiment_dir/bounded_faults.cpp" -o "$fault_binary"
"$fault_binary"
"${CXX:-g++}" -std=c++20 -O3 -pthread -DDNS_BOUNDED_TEST_HOOK "$experiment_dir/bounded_collision.cpp" -o "$collision_binary"
"$collision_binary"
"${CXX:-g++}" -std=c++20 -O3 -pthread -DDNS_HP_BOUNDED "$experiment_dir/hp_table_bench.cpp" -o "$bench_binary"
echo 'mode,threads,distribution,load,read_per_second,read_p50_ns,read_p99_ns,read_p999_ns,write_p99_ns,write_p999_ns,write_time_over_read_time,live_nodes,peak_nodes,checksum'
for threads in 1 4 8; do
    for distribution in hot uniform; do
        for mode in local mutex hazard; do
            "$bench_binary" "$mode" "$threads" "$distribution" read
        done
        for mode in mutex hazard; do
            "$bench_binary" "$mode" "$threads" "$distribution" update
        done
    done
done
