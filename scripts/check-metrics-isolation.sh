#!/usr/bin/env bash
# Fails when the test suite wrote to the real metrics ledgers (cadence-hooks#1586).
#
# Run it after `cargo test` on a machine whose config dir held no ledgers
# beforehand (a fresh CI runner). Every test that logs must point
# CADENCE_METRICS_DIR at a scratch dir; a row here means one did not.
#
# Usage: scripts/check-metrics-isolation.sh [CONFIG_DIR]
#   CONFIG_DIR defaults to $CLAUDE_CONFIG_DIR, else $HOME/.claude.
set -euo pipefail

main() {
    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        sed -n '2,9p' "$0"
        return 0
    fi
    local config_dir="${1:-${CLAUDE_CONFIG_DIR:-$HOME/.claude}}"
    # Both roots metrics_dir() can resolve to: the current one and the legacy one.
    local roots=("$config_dir/cadence/metrics" "$config_dir/metrics")
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
        echo "expected no ledger files under $config_dir after the suite; a test is logging without CADENCE_METRICS_DIR set to a scratch dir" >&2
        return 1
    fi
    echo "metrics isolation: no ledger rows under $config_dir"
}

main "$@"
