#!/usr/bin/env bash
set -euo pipefail

# Explicit, reviewed exceptions are listed here and in docs/development/file-sizes.md.
declare -A exceptions=(
    [experiments/dns-shared-cache/group_shared_capacity_test.cpp]="established baseline"
    [experiments/dns-shared-cache/group_singleflight_test.cpp]="established baseline"
    [experiments/dns-shared-cache/group_snapshot_test.cpp]="established baseline"
    [experiments/dns-shared-cache/proxy_group_bench.py]="established baseline"
    [src/build/mcpp_pinned_guard.cpp]="established baseline"
    [src/config/dns.cpp]="established baseline"
    [src/dns-shared/group_snapshot.hpp]="established baseline"
    [src/dns/cache.cppm]="established baseline"
    [src/http2/server.cppm]="established baseline"
    [src/proxy/proxy.cppm]="established baseline"
    [src/rules/matcher.cpp]="established baseline"
    [tests/config.cpp]="established baseline"
    [tests/detour_network.py]="established baseline"
    [tests/dns_message.cpp]="established baseline"
    [tests/http2/http2_server.cpp]="established baseline"
    [tests/http2/http2_tls_backpressure.cpp]="established baseline"
    [tests/rules_v2.cpp]="established baseline"
)
failed=0
checked=0

while IFS= read -r -d '' path; do
    checked=$((checked + 1))
    lines=$(awk 'END { print NR }' "$path")
    if (( lines > 500 )); then
        if [[ -n ${exceptions["$path"]:-} ]]; then
            printf 'EXEMPT %s: %s lines (%s)\n' "$path" "$lines" "${exceptions["$path"]}"
        else
            printf 'FAIL %s: %s lines (maximum 500)\n' "$path" "$lines" >&2
            failed=1
        fi
    elif (( lines > 300 )); then
        printf 'REVIEW %s: %s lines (target 300)\n' "$path" "$lines"
    fi
done < <(rg --files --hidden -0 \
    -g '!.git/**' -g '!target/**' \
    -g '!3rdparty/vendor/**' -g '!docs/**' \
    -g '*.c' -g '*.cc' -g '*.cpp' -g '*.cxx' -g '*.h' -g '*.hpp' \
    -g '*.hxx' -g '*.ixx' -g '*.cppm' -g '*.lua' -g '*.py' -g '*.sh' \
    -g '!3rdparty/modules/ngtcp2.cppm' -g '!3rdparty/modules/nghttp3.cppm' \
    -g '!3rdparty/mcpp-index/pkgs/n/nexus.corosio-source.lua' \
    -g '!3rdparty/mcpp-index/pkgs/n/nexus.capy-source.lua' \
    -g '!3rdparty/mcpp-index/pkgs/n/nexus.boringssl-crypto-source.lua')

printf 'Checked %s hand-written source files.\n' "$checked"
exit "$failed"
