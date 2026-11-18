## Why

Review of cameronsjo/cadence-hooks#1648 found two gaps between the `external-content` spec and the shipped `warn-overshare`. The triggers requirement never names a commit, though a commit has always triggered the reminder through the shared posting gate. And the quiet period was spent when the check decided to remind, so a reminder that repo configuration suppressed still used up the session's one reminder.

## What Changes

- MODIFY "Overshare audit triggers": name `git commit` as a trigger, and name the three things the reminder asks the model to check (health, relationships, non-technical biography), which the reminder text already carries and a test now pins. No behavior changes.
- ADD "Overshare quiet period spending": the quiet period is spent only when the reminder is emitted. A reminder that repo configuration suppresses does not spend it, and a process that loses the per-event dedupe claim writes no marker.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `external-content`: one requirement modified, one added.

## Impact

- `cadence-hooks cadence warn-overshare`: the marker is now written by the dispatcher after it emits the reminder, not by the check.
- `crates/cadence/src/warn_overshare.rs`, `src/dispatch.rs`, `tests/overshare_quiet_period.rs`, `openspec/specs/external-content/spec.md`.
