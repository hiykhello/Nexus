#!/usr/bin/env bash
set -euo pipefail
binary=${1:?provide the view memory experiment binary}
printf 'round,profiles,views,bindings,policy_charge,allocated_before,allocated_after,allocated_delta,rss_before_kib,rss_after_kib\n'
for round in 1 2 3; do
    for profiles in 1 2; do
        for views in 8 256 4096 8192; do
            printf '%s,' "$round"
            "$binary" "$profiles" "$views" "$((profiles*4))"
        done
    done
done
