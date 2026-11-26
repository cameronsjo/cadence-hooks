---
name: verify
description: Use before committing a change to a hook in this repo, or when polish asks for verify. Builds the real binary and pipes crafted payloads through each changed hook, at head and at the base, under a scratch metrics dir.
---

# Verify a cadence-hooks change

Tests prove the code does what the tests say. This proves the shipped binary does what the change claims: build it, feed each changed hook real payloads, and read the verdicts. Run it from the repo root on the branch you are about to commit, with `origin/main` merged in: the base side is `origin/main`, so an unmerged branch shows main's newer changes as if they were yours.

## 1. Build both binaries

`cargo test` does not build the binary, and a missing binary exits 127, which reads like an ALLOW.

```bash
export PATH="$HOME/.cargo/bin:$PATH"
V="$(mktemp -d)"; mkdir "$V/payloads" "$V/metrics" "$V/markers" "$V/home" "$V/tmp"
CARGO_TARGET_DIR="$PWD/target" cargo build --bin cadence-hooks \
  && git fetch -q origin main \
  && git worktree add -q --detach "$V/base" origin/main \
  && (cd "$V/base" && CARGO_TARGET_DIR="$V/target" cargo build --bin cadence-hooks) \
  && echo BUILD-OK
HEAD_BIN="$PWD/target/debug/cadence-hooks"
BASE_BIN="$V/target/debug/cadence-hooks"
```

Go on only if it printed `BUILD-OK`: an old binary left in a target dir would give stale verdicts. If you stop here or later, still run the cleanup at the end. When the change only adds a new hook, skip the base build and leave `BASE_BIN` empty: the loop below then records `n/a` for base. When it adds one hook and changes others, keep the base build: the new hook's base rows print ERROR because the base binary has no such hook, and you record them as `n/a`.

## 2. Name the hooks the change touches

Map each changed `crates/<ns>/src/<file>.rs` to its hook with `$HEAD_BIN list`. A change to `crates/core/` reaches every hook that calls it: grep the callers and pick the ones the change could move.

## 3. Write the payloads

One JSON file per case in `$V/payloads/<hook>/`, named for the case, so each hook runs only its own payloads. For each changed hook:

- **The claim.** Each case the change says it fixes or adds, with the verdict it should now give.
- **The everyday control.** At least three routine commands or edits the hook sees daily (`git status`, `git push origin feature`, a plain Write). These must stay ALLOW, or the change is a new false block (CLAUDE.md, ADR-0046 rule 4).
- **A known red.** One case the hook already blocks or nudges at base. It proves the table can show something other than ALLOW. For a new hook there is no base verdict: use a case the head does not ALLOW.
- **The shape owner.** Check the hook owns each payload's shape (reads vs writes, Bash vs Write). A payload sent to the wrong guard reads as a false ALLOW.

```json
{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"},"session_id":"verify","cwd":"$V/repo"}
```

Write the real path into the file (expand `$V` when you generate it); a literal `$V` is not a directory.

## 4. Run them at head and at the base

Run it once per changed hook, with `<ns> <hook>` and the payload dir set to that hook. Each try runs under `env -i`: an empty environment plus a short allowlist (`PATH`, a scratch `HOME` and `TMPDIR`, and scratch metrics and marker dirs). The binary reads dozens of variables, and any one left over from your shell can change a verdict or write to real state:

- **Exemptions and escapes** turn a block into ALLOW: `CADENCE_DISABLE`, `CADENCE_BYPASS`, `CADENCE_ALLOW_MAIN`, `CADENCE_NO_ENFORCE_WORKTREE`, `CADENCE_ALLOW_SUBAGENT_FROM_MAIN`, `CADENCE_ALLOW_BRANCH_INTENT`, `CADENCE_ALLOW_SECRET_PUSH`, `CADENCE_ALLOW_SECRET_OUTPUT`, `CADENCE_ALLOW_SENSITIVE_TERMS`, `CADENCE_ALLOW_CRITICAL_GRADE`, `CADENCE_ALLOW_SOPS_DECRYPT`, `CADENCE_ALLOW_UNSCRUBBED_RUNBOOK`, `CADENCE_SKIP_OVERSHARE_AUDIT`, `CADENCE_NO_DAILY_GATE`, `CADENCE_NO_PERSIST_PLAN`, `CADENCE_NO_OUTRO_BACKSTOP`.
- **Policy inputs** change what counts as owned, sensitive or held: `CADENCE_ALLOWED_OWNERS`, `CADENCE_ALLOWED_REPOS` (and the legacy `GIT_GUARDRAILS_ALLOWED_*`), `GH_REPO`, `GH_HOST`, `GITLAB_HOST`, `GITEA_INSTANCE_URL`, `CADENCE_REDACTION_TERMS`, `CADENCE_AUDIENCE`, `CADENCE_ISSUE_TRACKER(S)`, `CADENCE_DRAIN_HELD`, `CADENCE_GUARD_DOTFILES`, `CADENCE_READ_MODEL_GUARD_*`, `CADENCE_RUNBOOKS_DIR`, `OBSIDIAN_VAULT`, `CLAUDE_CODE_REMOTE`, `CLAUDECODE`, `AI_AGENT`, `CLAUDE_EFFORT`, `GIT_DIR`, `GIT_WORK_TREE`, `CDPATH`.
- **State locations** decide where markers, ledgers and config are read and written: `CADENCE_METRICS_DIR`, `CADENCE_MARKER_DIR` (a nudge that already fired in a live session reads as ALLOW, and a probe uses up a live session's nudge), `CLAUDE_CONFIG_DIR`, `CLAUDE_PROJECT_DIR`, `CADENCE_PLANS_DIR`, `HOME`, `XDG_CONFIG_HOME`, `GH_CONFIG_DIR`, `TMPDIR`, `CLAUDE_CODE_SESSION_ID`.

The list comes from `rg 'env::var' crates/*/src src` and the `const ..._VAR` names beside them; re-run it when a hook adds a variable. A claim case that needs one (most often `CADENCE_ALLOWED_OWNERS=<owner>` for an ownership guard, since the scratch `HOME` has no saved config) adds it to `CASE_ENV` for that hook, and the PR table says so. The scratch `HOME` also means `gh` has no login, so a hook that asks GitHub sees an unauthenticated `gh`.

```bash
CASE_ENV=""   # e.g. CASE_ENV="CADENCE_ALLOWED_OWNERS=<owner>"; space-separated, no spaces in values
for p in "$V"/payloads/<hook>/*.json; do
  for side in base head; do
    b="$BASE_BIN"; [ "$side" = head ] && b="$HEAD_BIN"
    printf '%s %s: ' "$(basename "$p")" "$side"
    [ -n "$b" ] || { echo n/a; continue; }
    out="$(env -i PATH="$PATH" HOME="$V/home" TMPDIR="$V/tmp" \
      CADENCE_METRICS_DIR="$V/metrics" CADENCE_MARKER_DIR="$V/markers" \
      $CASE_ENV "$b" try <ns> <hook> --payload "$p" 2>&1)"
    printf '%s\n' "$out" | sed -n 's/^Outcome: *//p' | grep . \
      || { echo "ERROR (no outcome line):"; printf '%s\n' "$out" | tail -3; }
  done
done
```

`try` keeps the `cwd` of a payload you give it; only its generated sample gets the shell's cwd. For a hook that reads git state, set `cwd` in the payload to a repo in the state the case needs (`git init` one under `$V`). A `cwd` that is not a repo can make a guard skip and ALLOW: before #1632, `guard-push-remote` allowed a push to a literal unowned URL from `/tmp`, and blocked it from a repo.

## 5. Read the result

- **PASS:** every claim case gives its stated verdict at head, every everyday control is ALLOW at head, and the known red is not ALLOW at base (at head for a new hook, whose base rows are `n/a`).
- **FAIL:** any claim case gives another verdict, any control is NUDGE or BLOCK at head, the known red is ALLOW (at base, or at head for a new hook), or any row says ERROR (other than a new hook's base rows). Fix it before committing.

Wiring is a separate check. If the change also needs a `hooks.json` entry in the cadence monorepo, a hook whose `if:` matches none of the commands it should see never runs. `tests/hook_registration_audit.rs` checks only that a Bash hook has an `if:` key, not what it matches, so read the filter by hand.

Report the table (case, expected, base, head) in the PR body, then clean up:

```bash
git worktree remove --force "$V/base"; rm -rf "$V"
```
