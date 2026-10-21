## Why

The code review of cameronsjo/cadence-hooks#1469 found three spec lines that say more or less than `guard-gh-write` does. No verdict changes; only the text does.

- #1469 dropped "a loop it cannot follow" from "gh writes the guard cannot place". That phrase also covered a loop the parser reads whose body changes directory, or that runs outside an owned non-fork repository. Those loops still block, but no requirement says so now.
- The unread-loop nudge and the strict block skip a write that names its repo as a `gh repo` positional (`gh repo edit owner/repo`), since the guard counts that as a target. The spec named only `-R` and a literal path.
- The strict block skips the writes the guard allows without an ownership check (`gh gist`, `gh repo fork`, `gh issue create --web`, an allowed owner's `orgs/<org>` api write), and fires only where the command shows a `for … in` or `while …; do` loop. The spec said it blocks every write with no `-R` or literal path.

Part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443).

## What Changes

- ADD a requirement for a loop the parser reads: a gh write with no `-R` blocks when the loop body changes directory or the directory is not an owned non-fork repository.
- MODIFY the unread-loop requirement: a `gh repo` positional counts as a target; the parse time budget is one of the ways the parser fails. Its strict sentence points to a new requirement; its two strict scenarios stay.
- ADD a strict-loops requirement for a loop the parser cannot read, scoped to what the guard does.

No code change. Surfaces: `openspec/specs/repo-ownership/spec.md`, `docs/configuration.md`, the #1469 CHANGELOG bullet.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: one requirement modified, two added.

## Impact

`openspec/specs/repo-ownership/spec.md`, `docs/configuration.md`, `CHANGELOG.md`.
