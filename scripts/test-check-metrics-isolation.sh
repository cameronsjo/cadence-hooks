#!/usr/bin/env bash
# Exercise scripts/check-metrics-isolation.sh on throwaway config dirs, so a
# check that can no longer fail is caught. ci.yml runs this before the check.
#
# Usage: bash scripts/test-check-metrics-isolation.sh [repo-root]
set -uo pipefail

WT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CHECK="$WT/scripts/check-metrics-isolation.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

# expect <name> <want-exit> [env assignments...] -- [check args...]
expect() {
    local name="$1" want="$2" rc out
    shift 2
    local envs=()
    while [[ $# -gt 0 && "$1" != "--" ]]; do envs+=("$1"); shift; done
    [[ $# -gt 0 ]] && shift
    out="$(env -u CLAUDE_CONFIG_DIR -u USERPROFILE -u HOMEDRIVE -u HOMEPATH ${envs[@]+"${envs[@]}"} bash "$CHECK" "$@" 2>&1)"; rc=$?
    if [[ "$rc" -eq "$want" ]]; then
        echo "ok   - $name"
    else
        echo "FAIL - $name (exit $rc, want $want)"
        printf '%s\n' "$out" | sed 's/^/       /'
        fails=$((fails + 1))
    fi
}

plant() { mkdir -p "$(dirname "$1")" && printf '{"sessionId":"x"}\n' > "$1"; }

mkdir -p "$TMP/empty"
expect "empty config dir passes" 0 -- "$TMP/empty"

plant "$TMP/current/cadence/metrics/denials.jsonl"
expect "a ledger in cadence/metrics fails" 1 -- "$TMP/current"

plant "$TMP/legacy/metrics/sweeps.jsonl"
expect "a ledger in the legacy metrics dir fails" 1 -- "$TMP/legacy"

plant "$TMP/segment/cadence/metrics/denials.20261031T000000Z-000.jsonl"
expect "a rotated segment fails" 1 -- "$TMP/segment"

mkdir -p "$TMP/home/.claude/cadence/metrics"
plant "$TMP/home/.claude/cadence/metrics/hooks.jsonl"
expect "default resolves to HOME/.claude" 1 "HOME=$TMP/home" --

plant "$TMP/cfg/cadence/metrics/hooks.jsonl"
expect "CLAUDE_CONFIG_DIR first comma entry wins" 1 "HOME=$TMP/empty" "CLAUDE_CONFIG_DIR= $TMP/cfg ,$TMP/empty" --
expect "a later comma entry is ignored" 0 "HOME=$TMP/empty" "CLAUDE_CONFIG_DIR=$TMP/empty,$TMP/cfg" --
expect "a blank first entry is skipped" 1 "HOME=$TMP/empty" "CLAUDE_CONFIG_DIR= ,$TMP/cfg" --

plant "$TMP/tilde/x/cadence/metrics/hooks.jsonl"
# shellcheck disable=SC2088 # the literal ~ is the input under test
expect "~/x expands against HOME" 1 "HOME=$TMP/tilde" "CLAUDE_CONFIG_DIR=~/x" --
mkdir -p "$TMP/bare/cadence/metrics"
plant "$TMP/bare/cadence/metrics/hooks.jsonl"
expect "a bare ~ is HOME" 1 "HOME=$TMP/bare" "CLAUDE_CONFIG_DIR=~" --
expect "a glob in the value is not expanded" 0 "HOME=$TMP/empty" "CLAUDE_CONFIG_DIR=$TMP/*" --

expect "USERPROFILE stands in for an unset HOME" 1 "HOME=" "USERPROFILE=$TMP/home" --
expect "no home at all refuses" 2 "HOME=" --

if [[ "$fails" -ne 0 ]]; then
    echo "$fails case(s) failed" >&2
    exit 1
fi
echo "all cases passed"
