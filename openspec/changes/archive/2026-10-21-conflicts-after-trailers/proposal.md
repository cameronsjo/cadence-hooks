## Why

A merge that stops on conflicts leaves git's own `# Conflicts:` block at the end of the pending message (MERGE_MSG), below any trailers the merge was started with. `git commit --no-edit` keeps `#` lines (its default cleanup is `whitespace`), so the commit lands with that block after its trailers. They are then no longer the final paragraph, and a lint or tool that reads the final paragraph misses them. The downstream lint caught it only after the commit was pushed (cameronsjo/cadence-hooks#1439).

`git commit --no-edit --cleanup=strip` drops the block, verified on a real conflicted merge. It also drops every other line that starts with `#`, an issue reference or a markdown heading in the body included, with no warning. So the nudge says what strip drops and gives the safe route for a message with such lines: commit a copy of MERGE_MSG cut at the `# Conflicts:` line with `-F`.

## What Changes

- `session warn-commit-provenance` nudges when a `git commit --no-edit` would finish a conflicted merge whose MERGE_MSG has trailers followed by `# Conflicts:`. The nudge names `git commit --no-edit --cleanup=strip`, warns that it drops every line starting with `#`, and names the `-F` route.
- It reads only the plain shape: `git commit` with no git option before the subcommand, `--no-edit`, and no message, cleanup or edit flag (`-m`, `-F`, `-C`, `-c`, `--cleanup`, `-e`/`--edit`). Anything it cannot read exactly stays silent.
- It never blocks, and it does not spend the once-per-session provenance marker.

Surfaces: `session warn-commit-provenance` (PreToolUse, Bash) and its nudge text. No hooks.json change: the existing `Bash(*git commit*)` filter already matches.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `session-coordination`: "Commit provenance trailer nudge" says an unreadable message draws no provenance nudge, instead of "MUST allow", so the new requirement can nudge on `--no-edit`. A new requirement covers the conflicted-merge nudge.

## Impact

`crates/session/src/warn_commit_provenance.rs`, `CHANGELOG.md`.
