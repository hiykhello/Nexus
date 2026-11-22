#!/usr/bin/env bash
set -euo pipefail
experiment_dir=$(cd "$(dirname "$0")" && pwd)
binary=$(mktemp)
trap 'rm -f "$binary"' EXIT
"${CXX:-g++}" -std=c++20 -O3 -pthread "$experiment_dir/bounded_miss.cpp" -o "$binary"
"$binary"
