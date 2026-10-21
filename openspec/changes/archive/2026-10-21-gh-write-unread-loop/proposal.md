## Why

The loop parser reads at most 12 KB. When it could not read a command, `guard-gh-write` blocked any loop that held a `gh` command, reads included ("gh command in loop — cannot verify targets"), so a long comment or heredoc in front of an ordinary loop blocked. Under cadence-ecosystem ADR-0046 rule 3 a guard judges what it read and does not refuse a command for being hard to read. This is part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443), shipped in cameronsjo/cadence-hooks#1469.

## What Changes

- A loop the loop parser cannot read is judged one gh write at a time, as outside a loop. A write to an unowned or unresolvable target still blocks (the ADR-0046 harm: a write to a repo the operator does not own).
- A judged write with no `-R`, `GH_REPO` or literal `repos/<owner>/<repo>/…` path gets a nudge naming `-R owner/repo`. A loop whose writes all name their target, or that only reads, is allowed.
- With `CADENCE_GH_STRICT_LOOPS=1`, a write in such a loop with no `-R` or literal path still blocks, as it does in a loop the parser reads.

Surfaces: `guard-gh-write` (PreToolUse, Bash), its exit code (2 to 0 for the shapes above), the nudge text, the strict-loops block text, and `CADENCE_GH_STRICT_LOOPS`. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: "gh writes the guard cannot place" drops the loop it cannot follow; a new requirement covers a loop the parser cannot read, strict loops included.

## Impact

`crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `tests/failopen_telemetry.rs`, `CHANGELOG.md`.
