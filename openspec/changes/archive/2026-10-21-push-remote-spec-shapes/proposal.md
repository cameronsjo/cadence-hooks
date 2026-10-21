## Why

The code review of cameronsjo/cadence-hooks#1470 found three lines that say more than `guard-push-remote` does, and review of this change found a fourth. Probes against the built binary confirm each one.

- The two nudges for a command the loop parser cannot read said "each push it read was checked on its own target". A bare push is checked against the branch checked out before the command runs. After a `git checkout` in the same command it pushes to that branch's remote, which the guard never read.
- "Push shapes the push guard refuses" said a bare push chained after a branch switch blocks. It blocks only in a chain of two or more pushes, and the switch can sit anywhere in the chain.
- The same requirement said more than four push directories block. The cap counts pushes behind `git -C` or a subshell `cd`, one per directory and remote pair, so five URLs pushed from one `git -C` directory block too. A top-level `cd` chain judges each push in its own directory, and a loop over five directories nudges.
- It also said more than four loop remotes block. A literal URL in a loop is checked without a lookup and does not count; only the remotes git has to look up do.

Part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443).

## What Changes

- Both unparsed nudges say a bare push was checked against the branch checked out now.
- MODIFY "Push shapes the push guard refuses" to name the push chain, the non-URL loop remotes, and the directory and remote pairs behind `git -C` or a subshell `cd`. Its three scenarios stay, and two are added.
- ADD a requirement that the unparsed nudges name the branch a bare push was checked against.

No verdict changes. Surfaces: the two nudge texts, `openspec/specs/repo-ownership/spec.md`, the #1470 CHANGELOG bullet.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: one requirement modified, one added.

## Impact

`crates/guardrails/src/guard_push_remote.rs`, `tests/failopen_telemetry.rs`, `CHANGELOG.md`.
