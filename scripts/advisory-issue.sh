#!/usr/bin/env bash
# Open, update, or close the tracking issue for RustSec advisories found by the
# weekly scheduled `cargo audit` run in .github/workflows/security.yml.
#
# Why an issue rather than a red build: a scheduled run has no pull request
# attached, so a failing job leaves `main` permanently red with nothing to merge
# against — a signal people learn to scroll past. PR and push runs still fail the
# build, because there the change that introduced the advisory is right there.
#
#   advisory-issue.sh report <report-file>   advisories found  -> open or comment
#   advisory-issue.sh resolve                run came back clean -> close if open
#
# Reentrant: `report` twice in a row comments rather than opening a duplicate,
# and `resolve` with no open issue is a no-op.
set -euo pipefail

readonly ISSUE_TITLE="security: RustSec advisories affecting main"
readonly ISSUE_LABEL="security"
readonly LABEL_COLOR="d73a4a"

if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
    readonly C_STEP=$'\033[36m' C_OK=$'\033[32m' C_BAD=$'\033[31m' C_OFF=$'\033[0m'
else
    readonly C_STEP='' C_OK='' C_BAD='' C_OFF=''
fi

step() { printf '%s==>%s %s\n' "$C_STEP" "$C_OFF" "$1" >&2; }
ok() { printf '%sSuccessfully%s %s\n' "$C_OK" "$C_OFF" "$1" >&2; }
die() { printf '%sFailed%s %s\n' "$C_BAD" "$C_OFF" "$1" >&2; exit 1; }

# The number of the open tracking issue, or empty. Matched on exact title rather
# than a search query so a similarly-worded issue can never be mistaken for it.
# Title comparison happens in awk, not inside the --jq program, so the constant
# is never interpolated into a query language.
find_open_issue() {
    gh issue list --state open --label "$ISSUE_LABEL" --limit 100 \
        --json number,title --jq '.[] | [(.number | tostring), .title] | @tsv' |
        awk -F'\t' -v want="$ISSUE_TITLE" '$2 == want { print $1; exit }'
}

ensure_label() {
    if gh label list --limit 200 --json name --jq '.[].name' | grep -qxF "$ISSUE_LABEL"; then
        return
    fi
    step "Label $ISSUE_LABEL missing on this repo, creating it."
    gh label create "$ISSUE_LABEL" --color "$LABEL_COLOR" \
        --description "Security advisories and hardening"
}

# Build the issue body in a file. Advisory text originates in the RustSec
# database — external input — so it reaches `gh` through --body-file and never
# through shell interpolation or a command substitution.
# shellcheck disable=SC2016 # the backticks are markdown, not substitutions.
write_body() {
    local report="$1" body="$2"
    {
        printf '`cargo audit` reported advisories against `Cargo.lock` on `main`.\n\n'
        printf 'Scheduled run: %s\n\n' "${RUN_URL:-unavailable}"
        printf 'This issue is opened, updated, and closed by `scripts/advisory-issue.sh`;\n'
        printf 'the next clean weekly run closes it.\n\n'
        printf '```text\n'
        # Strip ANSI escapes: cargo-audit suppresses color into a pipe, but a
        # future version deciding otherwise would corrupt the fenced block.
        sed $'s/\033\\[[0-9;]*m//g' "$report"
        printf '```\n'
    } >"$body"
}

cmd_report() {
    local report="${1:-}"
    [ -n "$report" ] || die "to report: no audit report path given."
    [ -f "$report" ] || die "to report: audit report $report does not exist."

    ensure_label
    local body
    body="$(mktemp)"
    # shellcheck disable=SC2064 # expand $body now: the trap outlives this scope.
    trap "rm -f '$body'" EXIT
    write_body "$report" "$body"

    local existing
    existing="$(find_open_issue)"
    if [ -n "$existing" ]; then
        step "Advisory issue #$existing already open, appending this run's report."
        gh issue comment "$existing" --body-file "$body" >/dev/null
        ok "updated advisory issue #$existing"
    else
        step "No advisory issue open, filing one."
        local url
        url="$(gh issue create --title "$ISSUE_TITLE" --label "$ISSUE_LABEL" --body-file "$body")"
        ok "filed advisory issue: $url"
    fi
}

cmd_resolve() {
    local existing
    existing="$(find_open_issue)"
    if [ -z "$existing" ]; then
        step "Audit is clean and no advisory issue is open. Nothing to resolve."
        return
    fi
    step "Audit is clean, closing advisory issue #$existing."
    gh issue close "$existing" --reason completed \
        --comment "A scheduled \`cargo audit\` run came back clean, so the tracked advisories no longer affect \`Cargo.lock\` on \`main\`. Run: ${RUN_URL:-unavailable}" >/dev/null
    ok "closed advisory issue #$existing"
}

case "${1:-}" in
    report) shift; cmd_report "$@" ;;
    resolve) cmd_resolve ;;
    *) die "to run: expected 'report <file>' or 'resolve', got '${1:-nothing}'." ;;
esac
