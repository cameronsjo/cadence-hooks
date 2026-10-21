## Why

`git-safety` blocked `git rebase main`, `git rebase -i master` and `git rebase --onto X Y main` as "Rebase onto protected branch", while `git rebase origin/main` only nudged. A rebase rewrites local history that the reflog restores, which cadence-ecosystem ADR-0046 rule 2 does not count as a costly harm. Part of cameronsjo/cadence-hooks#1443 (ADR-0046 phase 2), shipped in cameronsjo/cadence-hooks#1462.

## What Changes

- A `git rebase` naming `main` or `master` nudges instead of blocking, whatever its options.
- A rebase's nudge adds a line that names `git reflog` as the way back, since ADR-0046 rule 3 allows a nudge only when it names an action.
- A force push that names a protected branch still blocks, beside the rebase or inside its `--exec` script.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `git-safety`: the protected-branch block list loses its rebase clause, and the history nudge covers every rebase and names `git reflog` for it.

## Impact

- `cadence-hooks cadence git-safety` (PreToolUse, Bash): a rebase naming a protected branch exits 0 with the history nudge, not 2. The nudge for any rebase gains one line. No env var, config key, ledger or marker file changes.
- No hooks.json change in cameronsjo/cadence.
