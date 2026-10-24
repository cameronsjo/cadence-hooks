## Why

`git rm --cached .env` takes the file out of the index and leaves it on disk. `prevent-secret-writes` blocked it anyway: it read every `git rm` as `rm`, so `git rm --cached -r .env` and `git -C . rm --cached .env` blocked too (cameronsjo/cadence-hooks#1535). Untracking a committed `.env` is an everyday command. It neither writes nor deletes a secret, so under cadence-ecosystem ADR-0046 rule 2 there is no harm to block.

`trash-guard` already reads `--cached` (cameronsjo/cadence-hooks#1521), with its own copy of the rule. Two copies of one rule can drift apart. This is part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443).

## What Changes

- The `--cached` test moves to core (`git_rm_keeps_the_tree`), and both readers of `git rm` call it, so they cannot disagree.
- `prevent-secret-writes` reads a `git rm` with `--cached` among its options as no write target. `--cached` counts in any order with `-r`, `-q` and `-f`, before any `--` or `--end-of-options`, and as an unambiguous prefix (`--cach`); a later `--no-cached` undoes it.
- Unchanged: `git rm .env`, `git rm -- --cached .env` (a file named `--cached`, then `.env`), `git rm --cached --no-cached .env`, and a writing or deleting command beside the `git rm --cached` still block. `trash-guard`'s verdicts do not change.

Surfaces: `prevent-secret-writes` (PreToolUse, Bash) and its exit code (2 to 0 for an index-only `git rm` of a secret file). No message text changes. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `secret-writes`: "A git rm that leaves the file on disk is allowed" is added, and "Writer verbs targeting a secret file block" points to it.

## Impact

`crates/core/src/shell.rs`, `crates/cadence/src/prevent_secret_writes.rs`, `crates/obsidian/src/trash_guard.rs`, `CHANGELOG.md`.
