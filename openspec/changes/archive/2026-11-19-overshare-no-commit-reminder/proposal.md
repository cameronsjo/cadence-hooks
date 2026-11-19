## Why

cameronsjo/cadence-hooks#1636: `warn-overshare` fires too often. The quiet period from cameronsjo/cadence-hooks#1648 (one reminder per session on a plain `git commit`) cut only 0.1% to 0.5% of firings, because almost every commit carries a substitution, a `cd`, a `git -C` or a chain. Commits that are not chained with a push or a post are 16% to 36% of all firings. A commit leaves the machine only when it is pushed, and the push still reminds, so the commit reminder adds nothing a later reminder does not already give.

## What Changes

- MODIFY "Overshare audit triggers": a `git commit` is no longer a trigger. A Bash command that holds a commit and also a push or a post still reminds, for the push or the post. The requirement text stays under the strict validator's 500-character limit, so the commit rule itself sits in a new requirement. OpenSpec refuses a MODIFIED block that drops a scenario, so the old "Commit nudges" scenario stays by name and now describes a commit chained with a push.
- ADD "Overshare commit exemption": a commit alone stays silent in every form; with a push or a post it still reminds.
- REMOVE the four quiet-period requirements from #1648 (the quiet period, its spending, the plain-commit shape, its key). A commit that never reminds has no reminder to spend.
- No change to which pushes, posts or file edits remind. No change to the reminder text. The leak scan (`redact-external-content`) keeps treating `git commit` as a posting command.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `external-content`: one requirement modified, one added, four removed.

## Impact

- `cadence-hooks cadence warn-overshare`: a commit-only command exits 0 with no output; the session marker `overshare-commit-warned` is no longer read or written.
- `crates/cadence/src/warn_overshare.rs`, `crates/cadence/src/redact_external_content.rs` (a posting-gate variant without the commit arm), `src/dispatch.rs`, `docs/hooks.md`, `CHANGELOG.md`, `openspec/specs/external-content/spec.md`.
- `tests/overshare_quiet_period.rs` is deleted.
