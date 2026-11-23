## Why

`session lint-plan-shape` blocks `ExitPlanMode` unless the first `Panel:` line matches one of two exact forms. Transcripts show about 4 of 5 blocks were plans that already recorded their panel: `Panel: skipped — <reason>`, `3 seats ran (…) — 57 findings`, `seat — 2 HIGH, all folded`, or a bolded `**Panel:** none — …`. No `Panel: pending` line was ever presented; the accident the gate exists for is a missing line. Each false block costs a round trip and a ~900-character message, most of which does not help the fix. The gate also nudges for `## Concessions`, which the plan template renamed to `## Workarounds` (cameronsjo/cadence-hooks#1675).

## What Changes

- A `Panel:` line settles when it states an outcome. It is unsettled when its value is trivial, starts with `pending`, `tbd` or `todo`, carries an unfilled template placeholder (`<…>`, `[<`, or a value wrapped in `[…]`), or is `none`, `skipped` or `skip` with a trivial reason.
- `**Panel:** x`, `**Panel: x**` and `__Panel:__ x` are read as `Panel: x`.
- The block message carries only the fix: the first `Panel:` line is the one judged (replace it, don't add another), then the two canonical shapes. The advisory stanza list and both presentation reminders stay on the allow nudges.
- `## Workarounds` or `## Concessions` satisfies the workarounds stanza; the nudge names `a ## Workarounds section`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `plan-lifecycle`: "Plan-shape gate blocks only on the Panel line" shortens the block; "Plan-shape gate nudges and reminders" carries the reminders on allow outcomes only and accepts `## Workarounds`; "Panel line states an outcome" is added and says which lines settle.

## Impact

- `cadence-hooks session lint-plan-shape` and the persist-time format-gate sentence of `session persist-plan-approval`, which share the detector. Plans that blocked on a stated panel now allow; no plan that allowed before blocks.
