## Why

The code review of cameronsjo/cadence-hooks#1470 found three lines that say more than `guard-push-remote` does, and review of this change found more. Probes against the built binary confirm each one.

- The two nudges for a command the loop parser cannot read said "each push it read was checked on its own target". A bare push is checked against the branch checked out before the command runs. After a `git checkout` in the same command it pushes to that branch's remote, which the guard never read. "Pushes in a chain or loop the parser cannot read" said the same.
- "Push shapes the push guard refuses" said a bare push chained after a branch switch blocks. It blocks only in a chain of two or more pushes, and the switch can sit anywhere in the chain. The block's own text said "after a branch switch" too.
- The same requirement said more than four push directories block. The cap counts each directory and remote pair outside the directory the command's last top-level `cd` leaves it in: `git -C`, a subshell `cd`, `pushd`, `env -C` and a `bash -c 'cd …'` all count, and five URLs pushed from one `git -C` directory block too. A loop over five directories nudges.
- It also said more than four loop remotes block. A literal URL in a loop is checked without a lookup and does not count; only the remotes git has to look up do.

Part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443).

## What Changes

- Both unparsed nudges say a bare push was checked against the branch checked out now.
- The chain block says it found the bare push "in a chain that also switches branch or changes tracking".
- MODIFY "Push shapes the push guard refuses" to name the push chain, the non-URL loop remotes, and the directory and remote pairs outside the command's last directory. Its three scenarios stay, and two are added.
- MODIFY "Pushes in a chain or loop the parser cannot read": each push is judged as it would be alone, a bare one against the branch checked out now. Its scenarios stay.
- ADD a requirement that the unparsed nudges say which branch a bare push was checked against.

No verdict changes. Surfaces: the two nudge texts, the chain block's text, `openspec/specs/repo-ownership/spec.md`, the CHANGELOG.

A single bare push after a switch (`git checkout main && git push`) is still checked against the branch checked out now; catching it would add a block, so it is noted on cameronsjo/cadence-hooks#1444, where a `pre-push` hook reads the real destination.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: two requirements modified, one added.

## Impact

`crates/guardrails/src/guard_push_remote.rs`, `tests/failopen_telemetry.rs`, `CHANGELOG.md`.
