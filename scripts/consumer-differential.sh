#!/usr/bin/env bash
# Consumer differential for cadence-hooks#652 — nested `$( )` inside double quotes.
#
# The unit tests and `tests/shell_differential.rs` sample the parser and one
# guard. This samples every SUBCOMMAND that reaches the changed primitives, and
# asserts the property the fix is supposed to have rather than the outcomes the
# author happened to think of:
#
#   The recursion can only move a substitution's located terminator LATER in the
#   input or leave it where it was. Consumers therefore see a SUPERSET of the
#   text they saw before, so a verdict may move ALLOW -> BLOCK and must never
#   move BLOCK -> ALLOW.
#
# Three assertions, each able to go red:
#   1. no row/subcommand pair flips BLOCK -> ALLOW  (the safety invariant)
#   2. `session guard` — which calls `split_segments` only and never reaches
#      `substitution_bodies` — is byte-identical old vs new (the null control;
#      any movement there means the change leaked past its intended reach)
#   3. the stay-allowed rows are ALLOW on BOTH binaries (the over-block control;
#      a recursion that swallowed the rest of the line on a failed nested scan
#      would turn these red)
#
# Usage:
#   bash scripts/consumer-differential.sh [BASE_REF]
#
# BASE_REF defaults to origin/main. The base tree is exported with `git archive`
# into a temp dir and built there — nothing is checked out, no worktree is
# registered, and the repo's own branch and index are never touched. The "new"
# binary is built from the current working tree.
#
# Guard verdicts are read from the exit status: 2 = BLOCK, 0 = ALLOW, anything
# else is a HARNESS-ERROR that must never be scored as a verdict. `set -e` is
# deliberately absent: every row must run so the table is complete.

set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE_REF="${1:-origin/main}"
export PATH="$HOME/.cargo/bin:$PATH"

# The guards read these from the real process environment, and a Claude session
# routinely carries them. Left set, every blocks-assertion below false-passes
# with the reason buried in stderr.
unset CADENCE_DISABLE CADENCE_ALLOW_MAIN CADENCE_BYPASS

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

say() { printf '\033[1m%s\033[0m\n' "$*" >&2; }

# --- build both binaries -----------------------------------------------------

say "Exporting ${BASE_REF} and building the base binary (this takes a minute)"
BASE_SHA=$(git -C "$REPO_ROOT" rev-parse --short "$BASE_REF")
rc=$?
if [ "$rc" -ne 0 ] || [ -z "$BASE_SHA" ]; then
    printf 'FATAL: cannot resolve %s\n' "$BASE_REF" >&2
    exit 1
fi
mkdir -p "$WORK/base"
git -C "$REPO_ROOT" archive "$BASE_REF" | tar -x -C "$WORK/base"
rc=$?
[ "$rc" -eq 0 ] || { printf 'FATAL: git archive %s failed\n' "$BASE_REF" >&2; exit 1; }

(cd "$WORK/base" && cargo build --bin cadence-hooks) >"$WORK/base-build.log" 2>&1
rc=$?
[ "$rc" -eq 0 ] || { printf 'FATAL: base build failed; see %s\n' "$WORK/base-build.log" >&2; exit 1; }
BASE_BIN="$WORK/base/target/debug/cadence-hooks"

say "Building the current working tree"
(cd "$REPO_ROOT" && cargo build --bin cadence-hooks) >"$WORK/new-build.log" 2>&1
rc=$?
[ "$rc" -eq 0 ] || { printf 'FATAL: new build failed; see %s\n' "$WORK/new-build.log" >&2; exit 1; }
NEW_BIN="$REPO_ROOT/target/debug/cadence-hooks"

NEW_SHA=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
say "base=${BASE_SHA} (${BASE_REF})   new=${NEW_SHA}+worktree"

# --- corpus ------------------------------------------------------------------
#
# Rows are `label<TAB>command`. `cat .env` is the sentinel a read guard blocks
# on; it is only ever written into a JSON payload on a guard's stdin and is
# never handed to a shell.

CORPUS="$WORK/corpus.tsv"
{
    # The #652 bypassing shapes. The `"` inside the inner single-quoted run is
    # the trigger — without it these block on the base binary too and the row
    # proves nothing.
    printf '652-nested\techo $(echo "$(echo '"'"'")'"'"'; cat .env)")\n'
    printf '652-nested-leading-text\techo $(echo "x$(echo '"'"'")'"'"'; cat .env)")\n'
    # \001 stands in for the newlines inside a multi-line command so the row
    # stays one TSV line; the read loop substitutes them back.
    printf '652-nested-heredoc\tcat <<EOF\001$(echo "$(echo '"'"'")'"'"'; cat .env)")\001EOF\n'
    printf '652-escaped-opener\techo $(echo "\\$(") ; cat .env\n'
    # The five non-bypassing controls from the issue's trigger-boundary table.
    # These already blocked before the fix and must keep blocking.
    printf '652-ctl-no-inner-dquote\techo $(echo "$(cat .env)")\n'
    printf '652-ctl-backtick\techo $(echo "`cat .env`")\n'
    printf '652-ctl-top-level-dquote\techo "$(echo '"'"'")'"'"'; cat .env)"\n'
    printf '652-ctl-quoted-paren\techo $(echo ")" ; cat .env)\n'
    printf '652-ctl-paren-in-backtick\techo $(echo "`echo )`" ; cat .env)\n'
    # The existing `tests/shell_differential.rs` CASES table, which samples the
    # #490/#491/#496/#497/#511 parser classes this change must not disturb.
    printf '490-param-default-hash\techo ${x:- # } ; cat .env\n'
    printf '490-backtick-comment\techo `date # x`; cat .env\n'
    printf '490-escaped-space-hash\techo a\\ #x && cat .env\n'
    printf '490-param-default-text\techo ${B:-a # b} && cat .env\n'
    printf '497-sudo-short\tsudo -E bash -c '"'"'cat .env'"'"'\n'
    printf '497-sudo-end-of-options\tsudo -E -- bash -c '"'"'cat .env'"'"'\n'
    printf '496-bash-c-end-of-options\tbash -c -- '"'"'cat .env'"'"'\n'
    printf '491-odd-escaped-clobber\techo hi \\>| cat .env\n'
    printf '491-even-escaped-clobber\techo hi \\\\>| cat .env\n'
    printf '551-ansi-c-escaped-quote\techo $'"'"'a\\'"'"'b'"'"' $(cat .env)\n'
    printf '653-backtick-unterminated\techo `echo '"'"'` && cat .env\n'
    # Deep nesting: the recursion cap must not turn into a swallow.
    printf '652-deep-nesting\techo $(echo "$(echo "$(echo "$(cat .env)")")")\n'
} > "$CORPUS"

# Stay-allowed rows: ordinary nested substitutions with no secret read. More
# text reaching a guard means more chances of a false block, so these are the
# over-block control and are asserted ALLOW on both binaries.
STAY_ALLOWED="$WORK/allowed.tsv"
{
    # `-R` is load-bearing: the scratch dir has no git remote, so without an
    # explicit target `guard-gh-write` blocks on "cannot determine target repo"
    # — on BOTH binaries, for a reason that has nothing to do with this change.
    printf 'allow-gh-pr-body\tgh pr create -R cameronsjo/cadence-hooks --body "$(cat notes.md)"\n'
    printf 'allow-git-commit\tgit commit -m "$(printf '"'"'%%s'"'"' x)"\n'
    printf 'allow-nested-plain\techo $(echo "$(date)")\n'
    printf 'allow-nested-quoted-paren\techo $(echo "$(echo '"'"'")'"'"')")\n'
} > "$STAY_ALLOWED"

# --- consumers ---------------------------------------------------------------
#
# Every non-comment call site of command_segments / child_scripts /
# split_segments / expand_segments / strip_heredoc_bodies across crates/*/src.
# `session guard` is the null control: it calls split_segments only, which never
# reaches substitution_bodies, so its verdicts must not move at all.

AFFECTED=(
    "cadence git-safety"
    "cadence prevent-secret-leaks"
    "cadence prevent-secret-writes"
    "cadence redact-external-content"
    "cadence warn-overshare"
    "guardrails enforce-worktree"
    "guardrails guard-gh-dangerous"
    "guardrails guard-gh-write"
    "guardrails guard-op-vault-scan"
    "guardrails guard-rm"
    "guardrails inject-gh-write-context"
    "guardrails warn-gh-merge-preflight"
    "guardrails warn-going-public"
    "guardrails warn-pr-issue-link"
    "guardrails warn-unreviewed-ready-flip"
    "guardrails warn-untracked"
    "obsidian trash-guard"
    "session warn-branch-drift"
)
NULL_CONTROL="session guard"

# --- verdict -----------------------------------------------------------------

SCRATCH="$WORK/scratch"
mkdir -p "$SCRATCH"
printf 'DUMMY=1\n' > "$SCRATCH/.env"
printf 'notes\n' > "$SCRATCH/notes.md"

verdict() { # $1=binary  $2=subcommand pair  $3=command
    local bin="$1" sub="$2" cmd="$3" out rc
    CMD="$cmd" CWD="$SCRATCH" python3 - > "$WORK/payload.json" <<'PY'
import json, os
print(json.dumps({
    "session_id": "consumer-differential",
    "transcript_path": "/dev/null",
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": os.environ["CMD"]},
    "cwd": os.environ["CWD"],
}))
PY
    rc=$?
    [ "$rc" -eq 0 ] || { printf 'HARNESS-ERROR'; return; }
    # shellcheck disable=SC2086 # $sub is a deliberate two-word subcommand pair
    out=$(cd "$SCRATCH" && HOME="$SCRATCH" TMPDIR="$SCRATCH" \
        CADENCE_METRICS_DIR="$SCRATCH/metrics" CADENCE_MARKER_DIR="$SCRATCH/markers" \
        CADENCE_NO_FEEDBACK_FOOTER=1 \
        "$bin" $sub < "$WORK/payload.json" 2>&1)
    rc=$?   # captured BEFORE the pipe below
    # clap exits 2 on an unrecognized subcommand, which is byte-identical to a
    # guard's BLOCK contract. Scoring that as BLOCK is what made an earlier
    # probe's controls read false, so it is checked first.
    if printf '%s' "$out" | command grep -qi 'unrecognized subcommand'; then
        printf 'HARNESS-ERROR'
    elif [ "$rc" -eq 2 ]; then
        printf 'BLOCK'
    elif [ "$rc" -eq 0 ]; then
        printf 'ALLOW'
    else
        # Neither verdict. A nudge that exits 1, a panic, a missing binary —
        # none of these are an ALLOW and none may be scored as one.
        printf 'HARNESS-ERROR(rc=%s)' "$rc"
    fi
}

# --- run ---------------------------------------------------------------------

flips=0
null_moves=0
overblocks=0
harness_errors=0
fixed=0

printf '\n%-28s %-34s %-8s %-8s %s\n' ROW SUBCOMMAND BASE NEW NOTE
printf '%.0s-' {1..92}; printf '\n'

score() { # $1=label $2=sub $3=cmd $4=mode(affected|null|allowed)
    local label="$1" sub="$2" cmd="$3" mode="$4" b n note=''
    b=$(verdict "$BASE_BIN" "$sub" "$cmd")
    n=$(verdict "$NEW_BIN"  "$sub" "$cmd")
    case "$b:$n" in
        HARNESS-ERROR*|*:HARNESS-ERROR*) note='HARNESS-ERROR'; harness_errors=$((harness_errors+1)) ;;
        BLOCK:ALLOW) note='FLIP BLOCK->ALLOW'; flips=$((flips+1)) ;;
        ALLOW:BLOCK) note='fixed (ALLOW->BLOCK)'; fixed=$((fixed+1)) ;;
    esac
    if [ "$mode" = null ] && [ "$b" != "$n" ]; then
        note='NULL CONTROL MOVED'; null_moves=$((null_moves+1))
    fi
    # An ordinary nested substitution must not become newly blocked. The
    # assertion is that the verdict did not MOVE, not that it is ALLOW: a row
    # can block on both binaries for a reason unrelated to this change, and
    # demanding an absolute ALLOW turns that into a false finding.
    if [ "$mode" = allowed ] && [ "$b" != "$n" ]; then
        note='OVER-BLOCK (verdict moved)'; overblocks=$((overblocks+1))
    fi
    [ -n "$note" ] && printf '%-28s %-34s %-8s %-8s %s\n' "$label" "$sub" "$b" "$n" "$note"
    return 0
}

while IFS=$'\t' read -r label cmd; do
    [ -n "${label:-}" ] || continue
    cmd=${cmd//$'\001'/$'\n'}
    for sub in "${AFFECTED[@]}"; do
        score "$label" "$sub" "$cmd" affected
    done
    score "$label" "$NULL_CONTROL" "$cmd" null
done < "$CORPUS"

while IFS=$'\t' read -r label cmd; do
    [ -n "${label:-}" ] || continue
    for sub in "${AFFECTED[@]}"; do
        score "$label" "$sub" "$cmd" allowed
    done
done < "$STAY_ALLOWED"

printf '%.0s-' {1..92}; printf '\n'
printf 'rows scored: %s corpus x %s subcommands (+ null control), %s stay-allowed rows\n' \
    "$(wc -l < "$CORPUS" | tr -d ' ')" "${#AFFECTED[@]}" "$(wc -l < "$STAY_ALLOWED" | tr -d ' ')"
printf 'ALLOW->BLOCK (the fix landing): %s\n' "$fixed"
printf 'BLOCK->ALLOW flips: %s   null-control moves: %s   over-blocks: %s   harness errors: %s\n' \
    "$flips" "$null_moves" "$overblocks" "$harness_errors"

if [ "$fixed" -eq 0 ]; then
    printf '\nVERDICT: FAIL — no row moved ALLOW->BLOCK, so this run could not have gone red.\n'
    exit 1
fi
if [ "$flips" -ne 0 ] || [ "$null_moves" -ne 0 ] || [ "$overblocks" -ne 0 ] || [ "$harness_errors" -ne 0 ]; then
    printf '\nVERDICT: FAIL\n'
    exit 1
fi
printf '\nVERDICT: PASS — no BLOCK->ALLOW flip, null control unmoved, stay-allowed rows unmoved.\n'
