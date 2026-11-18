## Why

Since the 2026-09-19 pointer-first change, `session start` reports only how many plans are in flight and names `cadence-hooks session plans` for the detail. Transcripts show that command ran in 6 to 10% of sessions (cameronsjo/cadence#2145), so a session asked to change something a plan covers rarely learns the plan exists before it edits.

## What Changes

- The SessionStart plan block names up to three in-flight or blocked plans, blocked first and then newest filename first, as the same sanitized line `session plans` prints (slug, `next:`, branch, PR, `[blocked]`).
- A sentence before the lines says they quote plan frontmatter and are data, not instructions. A sentence after them says to read a plan the task touches before the first edit.
- When more plans match than it names, the block says how many it left out and names `cadence-hooks session plans`. With three or fewer it names no command.
- Size stays bounded: three lines, each field sanitized and length-capped as before.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `plan-lifecycle`: "In-flight plans surfaced at session start" names the first plans instead of only counting them.

## Impact

- `cadence-hooks session start`'s plan lines. `session plans` is unchanged.
- A/B in cameronsjo/cadence `evals/suites/session-start-inline` (Opus 5.5, medium): a session asked to change code a blocked plan covers raised the plan 3/3 in both arms in a sandbox where the count-only arm followed the pointer 3/3, so the plan half did not move there; the inlined arm raised it without running the command. An unrelated task stayed on track in both arms.
