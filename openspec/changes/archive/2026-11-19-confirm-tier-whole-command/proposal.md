## Why

Review round 2 of cameronsjo/cadence-hooks#1659 (cameronsjo/cadence-hooks#1658) found that `guard-op-vault-scan`'s confirm key still missed ordinary ways of choosing the 1Password identity: `export OP_ACCOUNT=b; op item list`, `op signin --account b && op item list`, `eval $(op signin --account b) && op item list`, and a different `--session`. Round 1 had added the account flag and an inline prefix; each round found the next selector. The owner's decision: stop listing selectors and key the guard on the whole command.

A probe through the binary found the same exposure in `guard-held-close`: after a confirm of `gh issue close 354`, `export GH_REPO=cameronsjo/free; gh issue close 354` passed as `confirmed`, because the guard reads the same held entry while `gh` closes in the exported repo. `enforce-worktree` showed none: `cd`, `git -C`, a `GIT_DIR=` prefix, `export GIT_DIR` and `--git-dir` each moved the judged repo or made the target unread, and every one blocked on the retry.

## What Changes

- MODIFY `hook-protocol` Confirm tier: the key is hook, session, agent and an action the guard names, which is either what it read (`enforce-worktree`) or the whole command normalized for spaces and tabs (`guard-op-vault-scan`, `guard-held-close`). The armed line says which retry pairs.
- MODIFY `hook-protocol` One confirmed row per confirmation: for `enforce-worktree`, the 30-minute snooze is already armed when another hook blocks the confirmed call.
- MODIFY `secret-reads` Confirmed vault listing: keyed by the whole command beside the scans it holds. REMOVE `secret-reads` Vault listing account: the whole command covers it.
- MODIFY `issue-guards` Confirmed HELD close: keyed by the held entries hit beside the whole command.
- `scripts/confirm-tier-compare.py` runs hermetically in a neutral temp directory.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `hook-protocol`: Confirm tier; One confirmed row per confirmation.
- `secret-reads`: Confirmed vault listing modified; Vault listing account removed.
- `issue-guards`: Confirmed HELD close.

## Impact

- `crates/core/src/confirm.rs` (`whole_command_action`, `Retry`), `crates/guardrails/src/guard_op_vault_scan.rs`, `crates/cadence/src/guard_held_close.rs`, `crates/guardrails/src/enforce_worktree.rs` (the `Retry` argument only).
- `scripts/confirm-tier-compare.py`, `docs/configuration.md`, `CHANGELOG.md`.
