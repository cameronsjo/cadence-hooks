## MODIFIED Requirements

### Requirement: Audit ledgers
Hooks SHALL append JSONL rows under the metrics directory (`CADENCE_METRICS_DIR` when non-empty, else `<config_dir>/cadence/metrics`, or an existing legacy `<config_dir>/metrics`). `denials.jsonl` gets a row per deny, ask or nudge; `bypasses.jsonl` a row when a switch or escape let an operation through (an env switch once per session and hook); `failopen.jsonl` a row per fail-open path; `hooks.jsonl` a row for a hook slower than `CADENCE_HOOK_TIMING_THRESHOLD_MS` (default 1000).

#### Scenario: Denial row
- **WHEN** `cadence git-safety` blocks `git reset --hard`
- **THEN** `denials.jsonl` gains a row with `"hook":"git-safety"` and `"decision":"deny"`

#### Scenario: Nudge rows opted out
- **WHEN** `CADENCE_LOG_NUDGES=0` is set and a hook nudges
- **THEN** no `denials.jsonl` row is written for the nudge

#### Scenario: Env switch used twice in one session
- **WHEN** `CADENCE_ALLOW_MAIN` lets two commits through `enforce-worktree` in one session
- **THEN** `bypasses.jsonl` gains one `used` row for that session, hook and mechanism

#### Scenario: Fail-open reasons
- **WHEN** a hook fails open
- **THEN** the `failopen.jsonl` row's `reason` is one of `parse`, `panic`, `version_mismatch`, `unreadable_input`, `schema_drift`, `deadline`, `deadline_block_suppressed`, `group_deadline`, `group_spawn` or `unjudged`
