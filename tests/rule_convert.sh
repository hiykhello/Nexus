#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
    printf 'usage: %s /path/to/nexus\n' "$0" >&2
    exit 2
fi
binary=$(realpath "$1")
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
expect_failure() {
    if "$@" >"$temporary/failure.log" 2>&1; then fail "command unexpectedly succeeded: $*"; fi
}

cat >"$temporary/input one.kdl" <<'EOF'
schema-version 1
kind "predicate"
rule type="domain-suffix" value="Example.COM"
rule type="ip-cidr" value="192.0.2.0/24"
EOF
cat >"$temporary/input-two.kdl" <<'EOF'
schema-version 1
kind "predicate"
rule type="domain-suffix" value="second.example"
EOF

"$binary" rule convert kdl beve "$temporary/input one.kdl" "$temporary/one.beve"
"$binary" rule convert beve kdl "$temporary/one.beve" "$temporary/roundtrip.kdl"
"$binary" rule convert kdl beve "$temporary/roundtrip.kdl" "$temporary/roundtrip.beve"
cmp -s "$temporary/one.beve" "$temporary/roundtrip.beve" || fail 'roundtrip differs'
"$binary" rule convert kdl beve "$temporary/input-two.kdl" "$temporary/two.beve"
[[ $(stat -c '%a' "$temporary/one.beve") == 600 ]] || fail 'output mode is not private'

printf 'existing output\n' >"$temporary/existing"
cp "$temporary/existing" "$temporary/existing-copy"
expect_failure "$binary" rule convert kdl beve "$temporary/input one.kdl" "$temporary/existing"
cmp -s "$temporary/existing" "$temporary/existing-copy" || fail 'existing output changed'
cp "$temporary/input one.kdl" "$temporary/source-copy"
expect_failure "$binary" rule convert kdl beve "$temporary/input one.kdl" "$temporary/input one.kdl"
cmp -s "$temporary/input one.kdl" "$temporary/source-copy" || fail 'input was overwritten'
ln "$temporary/input one.kdl" "$temporary/hardlink"
expect_failure "$binary" rule convert kdl beve "$temporary/input one.kdl" "$temporary/hardlink"
cmp -s "$temporary/input one.kdl" "$temporary/source-copy" || fail 'hard-linked input changed'
ln -s "$temporary/input one.kdl" "$temporary/symlink"
expect_failure "$binary" rule convert kdl beve "$temporary/input one.kdl" "$temporary/symlink"
[[ -L "$temporary/symlink" ]] || fail 'output symlink changed'
cmp -s "$temporary/input one.kdl" "$temporary/source-copy" || fail 'symlink target changed'

printf 'schema-version 3\nkind "predicate"\n' >"$temporary/invalid.kdl"
expect_failure "$binary" rule convert kdl beve "$temporary/invalid.kdl" "$temporary/invalid-output"
[[ ! -e "$temporary/invalid-output" ]] || fail 'invalid input produced output'
head -c 20 "$temporary/one.beve" >"$temporary/truncated.beve"
expect_failure "$binary" rule convert beve kdl "$temporary/truncated.beve" "$temporary/truncated-output"
[[ ! -e "$temporary/truncated-output" ]] || fail 'truncated input produced output'
truncate -s 33554433 "$temporary/oversize.kdl"
expect_failure "$binary" rule convert kdl beve "$temporary/oversize.kdl" "$temporary/oversize-output"
[[ ! -e "$temporary/oversize-output" ]] || fail 'oversize input produced output'
mkfifo "$temporary/fifo"
expect_failure timeout 5 "$binary" rule convert kdl beve "$temporary/fifo" "$temporary/fifo-output"
[[ ! -e "$temporary/fifo-output" ]] || fail 'FIFO produced output'
expect_failure "$binary" rule convert kdl beve "$temporary/input one.kdl" "$temporary/missing/output"
expect_failure "$binary" rule convert kdl kdl "$temporary/input one.kdl" "$temporary/same-format"

{
    printf 'schema-version 1\nkind "predicate"\n'
    for ((i = 0; i < 200; ++i)); do printf 'rule type="domain-suffix" value="example.com"\n'; done
} >"$temporary/large.kdl"
if (trap '' XFSZ; ulimit -f 1; "$binary" rule convert kdl beve "$temporary/large.kdl" "$temporary/write-failure" \
    >"$temporary/write-failure.log" 2>&1); then
    fail 'file-size limit should cause a write failure'
fi
[[ ! -e "$temporary/write-failure" ]] || fail 'failed write produced output'

for ((i = 0; i < 8; ++i)); do
    if ((i % 2)); then source="$temporary/input one.kdl"; else source="$temporary/input-two.kdl"; fi
    (if "$binary" rule convert kdl beve "$source" "$temporary/race.beve" >"$temporary/race-$i.log" 2>&1; then
        printf 'ok\n' >"$temporary/race-$i.result"
    else
        printf 'fail\n' >"$temporary/race-$i.result"
    fi) &
done
wait
[[ $(awk '$0 == "ok" {n++} END {print n+0}' "$temporary"/race-*.result) == 1 ]] || fail 'concurrent publication did not have exactly one winner'
cmp -s "$temporary/race.beve" "$temporary/one.beve" || cmp -s "$temporary/race.beve" "$temporary/two.beve" || fail 'race output is incomplete'
[[ -z $(find "$temporary" -maxdepth 1 -name '.nexus-rule-convert-*' -print -quit) ]] || fail 'temporary directory was left behind'
printf 'Rule conversion CLI tests passed\n'
