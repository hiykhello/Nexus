#!/usr/bin/env bash
set -euo pipefail

# Explicit, reviewed exceptions are listed here and in docs/development/file-sizes.md.
declare -A exceptions=()
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
    -g '!.git/**' -g '!build/**' -g '!target/**' -g '!.xmake/**' \
    -g '!3rdparty/vendor/**' -g '!docs/**' \
    -g '*.c' -g '*.cc' -g '*.cpp' -g '*.cxx' -g '*.h' -g '*.hpp' \
    -g '*.hxx' -g '*.ixx' -g '*.cppm' -g '*.lua' -g '*.py' -g '*.sh')

printf 'Checked %s hand-written source files.\n' "$checked"
exit "$failed"
