## Why

`git rm -n .env` and `git rm --dry-run .env` print what git would remove and exit. They change neither the index nor the file. `prevent-secret-writes` blocked them anyway, because it reads every `git rm` that lacks `--cached` as `rm` (cameronsjo/cadence-hooks#1547). Under cadence-ecosystem ADR-0046 rule 2, a command that destroys nothing has no harm to block. The code review of cameronsjo/cadence-hooks#1546, which lets `git rm --cached` through for the same reason, found it. This is part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443).

## What Changes

- A core test, `git_rm_is_dry_run`, sits beside `git_rm_keeps_the_tree`. It reads `-n` and `--dry-run` as git does: in any order before any `--` or `--end-of-options`, `-n` inside a cluster of `git rm`'s short flags (`-rn`, `-nf`), and `--dry-run` as an unambiguous prefix (`--dry`, `--d`). A later `--no-dry-run` (`--no-d`) undoes it.
- `prevent-secret-writes` reads a `git rm` dry run as no write target.
- Unchanged: `git rm .env`, `git rm -- -n .env` (a file named `-n`, then `.env`), `git rm -n --no-dry-run .env`, and a writing or deleting command beside the dry run still block. `trash-guard` does not call the new test, so its verdicts do not change.

Surfaces: `prevent-secret-writes` (PreToolUse, Bash) and its exit code (2 to 0 for a `git rm` dry run of a secret file). No message text changes. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `secret-writes`: "A git rm dry run is allowed" is added.

## Impact

`crates/core/src/shell.rs`, `crates/cadence/src/prevent_secret_writes.rs`, `CHANGELOG.md`.
