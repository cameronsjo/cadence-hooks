#!/usr/bin/env bash
# Fails when the test suite wrote to the real metrics ledgers (cadence-hooks#1586).
#
# Run it after `cargo test` on a machine whose config dir held no ledgers
# beforehand (a fresh CI runner). Every test that logs must point
# CADENCE_METRICS_DIR at a scratch dir; a row here means one did not.
# scripts/test-check-metrics-isolation.sh proves it fails on a planted leak.
#
# Usage: scripts/check-metrics-isolation.sh [CONFIG_DIR]
#   CONFIG_DIR defaults to the dir the binary resolves (claude_config_dir()).
set -euo pipefail

# The home dir as the binary sees it (crates/core/src/paths.rs resolve_home):
# HOME, else USERPROFILE, else HOMEDRIVE+HOMEPATH, converted to a POSIX path
# under Git Bash.
user_home() {
    local home="${HOME:-${USERPROFILE:-}}"
    if [[ -z "$home" && -n "${HOMEDRIVE:-}" && -n "${HOMEPATH:-}" ]]; then
        home="${HOMEDRIVE}${HOMEPATH}"
    fi
    if [[ -n "$home" ]] && command -v cygpath >/dev/null 2>&1; then
        home="$(cygpath -u "$home")"
    fi
    [[ "$home" == "/" ]] || home="${home%/}"
    printf '%s' "$home"
}

# Mirrors crates/core/src/paths.rs resolve_config_dir: the first non-empty
# comma entry of CLAUDE_CONFIG_DIR, `~`-expanded, else <home>/.claude.
config_dir() {
    local home entry entries
    home="$(user_home)"
    # read -a splits on the comma without pathname-expanding a * or ? in the value.
    IFS=',' read -ra entries <<<"${CLAUDE_CONFIG_DIR:-}"
    for entry in ${entries[@]+"${entries[@]}"}; do
        entry="${entry#"${entry%%[![:space:]]*}"}"
        entry="${entry%"${entry##*[![:space:]]}"}"
        [[ -n "$entry" ]] || continue
        # shellcheck disable=SC2088 # matching a literal ~ in the value, not expanding one
        case "$entry" in
            "~") printf '%s' "$home" ;;
            "~/"*) printf '%s/%s' "$home" "${entry#\~/}" ;;
            *) printf '%s' "$entry" ;;
        esac
        return 0
    done
    printf '%s/.claude' "$home"
}

main() {
    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        sed -n '2,10p' "$0"
        return 0
    fi
    local dir="${1:-$(config_dir)}"
    if [[ -z "$dir" || "$dir" == "/.claude" ]]; then
        echo "could not resolve a config dir (HOME and USERPROFILE unset); pass one as the first argument" >&2
        return 2
    fi
    # Both roots metrics_dir() can resolve to: the current one and the legacy one.
    local roots=("$dir/cadence/metrics" "$dir/metrics")
    local found=0 root file rows
    for root in "${roots[@]}"; do
        [[ -d "$root" ]] || continue
        while IFS= read -r file; do
            rows=$(wc -l <"$file" | tr -d ' ')
            echo "test rows leaked into a live ledger: $file ($rows rows)" >&2
            head -n 3 "$file" | cut -c1-200 >&2
            found=1
        done < <(find "$root" -type f \( -name '*.jsonl' -o -name '*.jsonl.*' \))
    done
    if [[ "$found" -ne 0 ]]; then
        echo "expected no ledger files under $dir after the suite; a test is logging without CADENCE_METRICS_DIR set to a scratch dir" >&2
        return 1
    fi
    echo "metrics isolation: no ledger files in ${roots[0]} or ${roots[1]}"
}

main "$@"
