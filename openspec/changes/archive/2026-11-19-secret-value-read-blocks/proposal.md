## Why

cameronsjo/cadence-hooks#1662: cadence-ecosystem ADR-0046 rule 2 lists a secret entering the context as a block kind, but `guard-secret-dump` only asks before a command prints a bare secret value (`op read`, `op item get --reveal`, `security find-*-password -w`). A yes puts the value in the transcript, and a leaked value has to be rotated, which cannot be undone. The operator, 2026-11-19: secrets should not enter the context, because then they are leaked and require rotation.

## What Changes

- MODIFY `secret-reads`: `guard-secret-dump` judges a bare value by where it goes. When the value would be the command's own output (the producer ends its pipeline with no redirect to a real file, a substitution in an `echo`/`printf` argument word (not `printf -v`) or as the whole first word holds it, or a `sh -c`/`eval` script prints it), the hook blocks (exit 2). It never joins the confirm tier.
- When the value goes to a consumer (a pipe, a substitution used as an argument, assignment or inline prefix, a here-string, a process substitution), the verdict stays the ask it is today. Contained shapes (a final hash, a real file) stay silent.
- The block message names consumer forms: pipe into the program that needs it, the clipboard, the tool's reference form (`op run`).
- State the limit: a consumer that itself prints the value, a later command that prints a variable, a script file, and a grouped script are outside what one command's text shows.
- `guard-op-vault-scan` is unchanged: its single-item reads either print nothing secret (`op item get --fields` without `--reveal` prints a placeholder for a concealed field) or are `guard-secret-dump`'s rows (`op read`, `--reveal`).
- Add `scripts/secret-dump-compare.py` and `scripts/testdata/secret-value-commands.txt`, the ADR-0046 rule 4 comparison for this change.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `secret-reads`: one requirement renamed and rewritten (where the value goes), one added (the producer table).

## Impact

- `crates/cadence/src/guard_secret_dump.rs`: `judge` returns a `Finding` with an `Exposure`; `run` blocks on `Printed`, asks on `Exposed`.
- Registry and CLI descriptions, `docs/hooks.md`, `docs/configuration.md`, CHANGELOG.
- No new escape: `CADENCE_DISABLE=guard-secret-dump` and `CADENCE_BYPASS=1` already switch the guard off for a person who needs to see a value.
