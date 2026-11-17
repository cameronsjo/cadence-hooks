---
name: verify
description: Use before committing a change to a hook in this repo, or when polish asks for verify. Builds the real binary and pipes crafted payloads through each changed hook, at head and at the base, under a scratch metrics dir.
---

# Verify a cadence-hooks change

Tests prove the code does what the tests say. This proves the shipped binary does what the change claims: build it, feed each changed hook real payloads, and read the verdicts. Run it from the repo root on the branch you are about to commit.

## 1. Build both binaries

`cargo test` does not build the binary, and a missing binary exits 127, which reads like an ALLOW.

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --bin cadence-hooks
V="$(mktemp -d)"; mkdir "$V/payloads"
git fetch -q origin main
git worktree add -q --detach "$V/base" origin/main
(cd "$V/base" && CARGO_TARGET_DIR="$V/target" cargo build --bin cadence-hooks)
HEAD_BIN="$PWD/target/debug/cadence-hooks"
BASE_BIN="$V/target/debug/cadence-hooks"
```

Skip the base build when the change adds a new hook: there is nothing to compare.

## 2. Name the hooks the change touches

Map each changed `crates/<ns>/src/<file>.rs` to its hook with `$HEAD_BIN list`. A change to `crates/core/` reaches every hook that calls it: grep the callers and pick the ones the change could move.

## 3. Write the payloads

One JSON file per case in `$V/payloads`, named for the case. For each changed hook:

- **The claim.** Each case the change says it fixes or adds, with the verdict it should now give.
- **The everyday control.** At least three routine commands or edits the hook sees daily (`git status`, `git push origin feature`, a plain Write). These must stay ALLOW, or the change is a new false block (CLAUDE.md, ADR-0046 rule 4).
- **The shape owner.** Check the hook owns each payload's shape (reads vs writes, Bash vs Write). A payload sent to the wrong guard reads as a false ALLOW.

```json
{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"},"session_id":"verify","cwd":"/tmp"}
```

## 4. Run them at head and at the base

Run under a scratch metrics dir, with the three exemption variables cleared. Otherwise every deny lands in the real `denials.jsonl`, and a disabled guard passes for the wrong reason.

```bash
export CADENCE_METRICS_DIR="$(mktemp -d)"
for p in "$V"/payloads/*.json; do
  for b in "$BASE_BIN" "$HEAD_BIN"; do
    printf '%s %s: ' "$(basename "$p")" "$([ "$b" = "$HEAD_BIN" ] && echo head || echo base)"
    env -u CADENCE_DISABLE -u CADENCE_ALLOW_MAIN -u CADENCE_BYPASS \
      "$b" try <ns> <hook> --payload "$p" | sed -n 's/^Outcome: *//p'
  done
done
```

`try` swaps the payload's `cwd` for the shell's cwd. For a hook that reads git state from `cwd`, pipe the payload to the bare `"$b" <ns> <hook>` instead and read the exit code: 2 is BLOCK, 0 with JSON on stdout is NUDGE, 0 with nothing is ALLOW.

## 5. Read the result

- **PASS:** every claim case gives its stated verdict at head, and no everyday control moved from ALLOW.
- **FAIL:** a claim case gives the old verdict, or any control moved ALLOW to BLOCK. Fix it before committing.
- A case that moved and is neither of these: name it in the PR body.

Wiring is a separate check. If the change also needs a `hooks.json` entry in the cadence monorepo, a hook with no matching `if:` never runs: `tests/hook_registration_audit.rs` covers that side.

Report the table (case, expected, base, head) in the PR body, then clean up:

```bash
git worktree remove --force "$V/base"; rm -rf "$V"
```
