## Why

`persist-plan-approval` has written approved plans to a repo's `CADENCE_PLANS_DIR` since 0.109.0, but every reader still scans `docs/plans/`. A repo that declares its own folder (a vault with `Meta/docs/plans`, or this repo with `.claude/plans`) gets its plans persisted where the SessionStart pointer, `session plans`, and the plan guards never look (cameronsjo/cadence#2153).

## What Changes

- The SessionStart plan pointer, the uncommitted-plan line, `session plans`, and the plan guards that read in-flight plans scan the repo's `CADENCE_PLANS_DIR` when it is set, valid, and inside the checkout, else `docs/plans/`.
- When a configured folder is in use and `docs/plans/` still exists, both are scanned, so plans written before the setting finish in place. This repo is one such case: its settings name `.claude/plans`, and an in-flight plan still sits in `docs/plans/`.
- Their output names every folder they scanned.
- A scan never creates the folder. An empty value (the persist opt-out) or a refused one falls back to `docs/plans/`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `plan-lifecycle`: "In-flight plans surfaced at session start" and "Plans CLI action" read the repo's plans folder instead of a fixed `docs/plans/`; "Plan readers use the repo's plans folder" is added and says which folder that is.

## Impact

- `cadence-hooks session start`, `cadence-hooks session plans`, and the plan guards' in-flight plan reads. Repos without `CADENCE_PLANS_DIR` see no change.
