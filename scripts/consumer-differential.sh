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
# Four assertions, each able to go red:
#   1. no row/subcommand pair flips BLOCK -> ALLOW  (the safety invariant)
#   2. the stay-allowed rows do not MOVE between the two binaries (the
#      over-block control; a recursion that swallowed the rest of the line on a
#      failed nested scan turns these red). The assertion is "did not move", not
#      "is ALLOW": a row can block on both binaries for a reason unrelated to
#      this change, and demanding an absolute ALLOW makes that a false finding.
#   3. `session warn-branch-drift` — which imports only `git_command` and
#      `strip_quotes` and reaches NEITHER changed primitive — does not move.
#      This is the leak control, and it is deliberately weak: it can only ever
#      catch a change that escaped the substitution scanners entirely.
#      `session guard` is NOT a valid control and was one in the first cut of
#      this script: `split_segments_with_ops` calls `strip_heredoc_bodies`,
#      which calls `substitution_spans`, so a CORRECT fix can move it.
#   4. the run produced at least one ALLOW -> BLOCK and at least one BLOCK
#      anywhere (a run that could not have gone red is not evidence)
#
# Usage:
#   bash scripts/consumer-differential.sh [BASE_REF]
#
# BASE_REF defaults to origin/main and MUST be a ref you trust: the base tree is
# built, so its `build.rs`, proc macros, and `.cargo/config.toml` execute. The
# tree is exported with `git archive` into a temp dir — nothing is checked out,
# no worktree is registered, and the repo's own branch and index are never
# touched — but "does not touch your checkout" is not "safe against any ref".
# The "new" binary is built from the current working tree.
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

# A ref beginning with `-` is parsed by git as an option, not an operand, so
# `--output=/tmp/x` would reach `git archive` as a flag. Nothing here is a shell
# sink, but an allowlist is cheaper than reasoning about which git subcommand
# accepts what, and `--` alone does not help `rev-parse`.
case "$BASE_REF" in
    -* | *[!A-Za-z0-9._/-]* | "")
        printf 'FATAL: refusing BASE_REF [%s] — must match [A-Za-z0-9._/-] and not start with -\n' \
            "$BASE_REF" >&2
        exit 1
        ;;
esac

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
    # Deep nesting at and past MAX_SUBSTITUTION_DEPTH (16), with the payload as
    # a SIBLING outside the deep chain — that placement is what makes the row
    # able to fail. The first cut of this script nested four levels against a
    # cap of sixteen, so the row named for the cap could never reach it, and the
    # differential ran green while a BLOCK -> ALLOW flip was live. The heredoc
    # wrapper is the shape that actually flipped: `substitution_spans` dropped
    # the construct where `substitution_bodies` widened.
    CHAIN=''; CLOSE=''
    for _ in $(seq 1 17); do CHAIN="\$(${CHAIN}"; CLOSE="${CLOSE})"; done
    CHAIN="${CHAIN}echo x${CLOSE}"
    printf '652-cap-plain\techo $(cat .env; %s)\n' "$CHAIN"
    printf '652-cap-heredoc\tcat <<EOF\001$(cat .env; %s)\001EOF\n' "$CHAIN"
    printf '652-cap-under\techo $(cat .env; %s)\n' \
        "$(c=''; e=''; for _ in $(seq 1 14); do c="\$(${c}"; e="${e})"; done; printf '%secho x%s' "$c" "$e")"
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
# split_segments / expand_segments / strip_heredoc_bodies across crates/*/src,
# mapped to the subcommand that reaches it. Derive this list, do not trust it:
# the first cut listed `session warn-branch-drift`, which imports only
# `git_command`/`strip_quotes` and is not a consumer at all, and omitted
# `session warn-plan-ready-flip` (crates/session/src/plan_guards.rs), which is.
#
# `session guard` belongs HERE, not in a control slot: `split_segments_with_ops`
# calls `strip_heredoc_bodies`, which calls `substitution_spans`, so this change
# reaches it.
#
# `src/doctor.rs` also calls `command_segments`, but `doctor` takes no hook
# payload on stdin, so it cannot be driven by this harness. Out of scope by
# mechanism, named here so its absence is a decision rather than an oversight.

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
    "session guard"
    "session warn-plan-ready-flip"
)
# Reaches neither changed primitive. Weak by construction (see the header):
# it can only catch a change that escaped the substitution scanners entirely.
LEAK_CONTROL="session warn-branch-drift"

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
    # Captured immediately, before the `grep` pipe further down — that pipe
    # would otherwise be the last command and `$?` would be grep's.
    rc=$?
    # clap exits 2 on an unrecognized subcommand, which is byte-identical to a
    # guard's BLOCK contract. Scoring that as BLOCK is what made an earlier
    # probe's controls read false, so it is checked first.
    if printf '%s' "$out" | command grep -qi 'unrecognized subcommand'; then
        printf 'HARNESS-ERROR'
    elif [ "$rc" -eq 2 ]; then
        printf 'BLOCK'
    elif [ "$rc" -eq 0 ]; then
        printf 'ALLOW'
    elif [ "$rc" -eq 1 ]; then
        # Guards fail open on their own internal errors (ADR-0001), so exit 1 is
        # a defined non-blocking outcome, not a fault — eight of the entries
        # above are `warn-*`/`inject-*` nudges. It is its own category: it must
        # never be scored ALLOW (that would hide a real movement), and it must
        # never fail the run (that would be a red unrelated to the change).
        printf 'SOFT'
    else
        # A panic, a signal, a missing binary. Not a verdict, and never an ALLOW.
        printf 'HARNESS-ERROR(rc=%s)' "$rc"
    fi
}

# --- run ---------------------------------------------------------------------

flips=0
leak_moves=0
overblocks=0
harness_errors=0
fixed=0
blocks_seen=0

printf '\n%-28s %-34s %-8s %-8s %s\n' ROW SUBCOMMAND BASE NEW NOTE
printf '%.0s-' {1..92}; printf '\n'

score() { # $1=label $2=sub $3=cmd $4=mode(affected|leak|allowed)
    local label="$1" sub="$2" cmd="$3" mode="$4" b n note=''
    b=$(verdict "$BASE_BIN" "$sub" "$cmd")
    n=$(verdict "$NEW_BIN"  "$sub" "$cmd")
    if [ "$b" = BLOCK ] || [ "$n" = BLOCK ]; then
        blocks_seen=$((blocks_seen+1))
    fi
    case "$b:$n" in
        HARNESS-ERROR*|*:HARNESS-ERROR*)
            note='HARNESS-ERROR'; harness_errors=$((harness_errors+1)) ;;
        BLOCK:ALLOW|BLOCK:SOFT)
            note='FLIP BLOCK->ALLOW'; flips=$((flips+1)) ;;
        # Only an affected row counts toward "the fix landed". A stay-allowed
        # row that moved this way is an over-block, and must not be able to
        # satisfy the could-this-have-gone-red gate below.
        ALLOW:BLOCK|SOFT:BLOCK)
            if [ "$mode" != allowed ]; then
                note='fixed (ALLOW->BLOCK)'; fixed=$((fixed+1))
            fi ;;
    esac
    if [ "$mode" = leak ] && [ "$b" != "$n" ]; then
        note='LEAK CONTROL MOVED'; leak_moves=$((leak_moves+1))
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
    score "$label" "$LEAK_CONTROL" "$cmd" leak
done < "$CORPUS"

while IFS=$'\t' read -r label cmd; do
    [ -n "${label:-}" ] || continue
    # Decoded here as well as in the corpus loop. No stay-allowed row is
    # multi-line today; leaving the two loops asymmetric is a trap for whoever
    # adds the first one.
    cmd=${cmd//$'\001'/$'\n'}
    for sub in "${AFFECTED[@]}"; do
        score "$label" "$sub" "$cmd" allowed
    done
done < "$STAY_ALLOWED"

printf '%.0s-' {1..92}; printf '\n'
printf 'rows scored: %s corpus x %s subcommands (+ leak control), %s stay-allowed rows\n' \
    "$(wc -l < "$CORPUS" | tr -d ' ')" "${#AFFECTED[@]}" "$(wc -l < "$STAY_ALLOWED" | tr -d ' ')"
printf 'ALLOW->BLOCK (the fix landing): %s   BLOCK verdicts seen: %s\n' "$fixed" "$blocks_seen"
printf 'BLOCK->ALLOW flips: %s   leak-control moves: %s   over-blocks: %s   harness errors: %s\n' \
    "$flips" "$leak_moves" "$overblocks" "$harness_errors"

# Could this run have gone red? Two independent ways it could not: the fix never
# landed on any row, or the harness never produced a BLOCK at all (a corpus that
# no guard reacts to scores every row ALLOW:ALLOW and reports a confident PASS).
if [ "$fixed" -eq 0 ]; then
    printf '\nVERDICT: FAIL — no row moved ALLOW->BLOCK, so this run could not have gone red.\n'
    exit 1
fi
if [ "$blocks_seen" -eq 0 ]; then
    printf '\nVERDICT: FAIL — no BLOCK verdict anywhere; the harness is not reaching the guards.\n'
    exit 1
fi
if [ "$flips" -ne 0 ] || [ "$leak_moves" -ne 0 ] || [ "$overblocks" -ne 0 ] || [ "$harness_errors" -ne 0 ]; then
    printf '\nVERDICT: FAIL\n'
    exit 1
fi
printf '\nVERDICT: PASS — no BLOCK->ALLOW flip, leak control unmoved, stay-allowed rows unmoved.\n'
