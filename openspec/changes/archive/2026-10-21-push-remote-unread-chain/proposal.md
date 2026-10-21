## Why

The loop parser reads at most 12 KB. When it could not read a command, `guard-push-remote` blocked any command with two pushes ("multiple git push commands — cannot verify targets") and any loop holding a push, so a long comment or heredoc in front of an ordinary chain or loop blocked. Under cadence-ecosystem ADR-0046 rule 3 a guard judges what it read and does not refuse a command for being hard to read. This is part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443), shipped in cameronsjo/cadence-hooks#1470.

## What Changes

- A chain or loop the loop parser cannot read (past its 12 KB cap, a heredoc or syntax error it cannot parse, or its 1 s parse budget) is judged one push at a time, as outside a chain or loop. A push to a remote the operator does not own still blocks (the ADR-0046 harm: a write to a repo the operator does not own).
- Several pushes in such a command get a nudge that names the cause and says to shorten the command or run each push as its own command.
- A command with a loop in it gets a nudge to give every push in the command an explicit remote, but only when a push in the command names no remote or one only the shell resolves (`$r`, a backtick). A loop whose pushes all name a literal remote is allowed.
- The "looped push with no explicit remote" block now covers only a loop the parser reads.

Surfaces: `guard-push-remote` (PreToolUse, Bash), its exit code (2 to 0 for the shapes above) and the two nudge texts. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: "Push shapes the push guard refuses" limits the looped-push block to a loop the parser reads; a new requirement covers a chain or loop the parser cannot read.

## Impact

`crates/guardrails/src/guard_push_remote.rs`, `crates/core/src/loop_analysis.rs` (a comment), `tests/failopen_telemetry.rs`, `CHANGELOG.md`.
