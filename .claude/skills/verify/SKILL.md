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
V="$(mktemp -d)"; mkdir "$V/payloads" "$V/metrics"
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
{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"},"session_id":"verify","cwd":"/tmp"}
```

## 4. Run them at head and at the base

Run it once per changed hook, with `<ns> <hook>` and the payload dir set to that hook. Run under a scratch metrics dir, with the three exemption variables cleared. Otherwise every deny lands in the real `denials.jsonl`, and a disabled guard passes for the wrong reason.

```bash
for p in "$V"/payloads/<hook>/*.json; do
  for side in base head; do
    b="$BASE_BIN"; [ "$side" = head ] && b="$HEAD_BIN"
    printf '%s %s: ' "$(basename "$p")" "$side"
    [ -n "$b" ] || { echo n/a; continue; }
    out="$(env -u CADENCE_DISABLE -u CADENCE_ALLOW_MAIN -u CADENCE_BYPASS \
      CADENCE_METRICS_DIR="$V/metrics" "$b" try <ns> <hook> --payload "$p" 2>&1)"
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
