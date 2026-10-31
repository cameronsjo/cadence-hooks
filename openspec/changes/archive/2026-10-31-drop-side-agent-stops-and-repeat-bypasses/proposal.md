## Why

Two ledgers were mostly repeats that answered nothing. In `subagents.jsonl`, 62,486 of 75,268 `SubagentStop` rows had no agent type, no Start, and no agent transcript (cameronsjo/cadence-hooks#1587). In `bypasses.jsonl`, 86% of rows were `CADENCE_ALLOW_MAIN` `used` rows repeated on every allowed call, up to 206 in one session (cameronsjo/cadence-hooks#1588).

## What Changes

- `log-subagent` writes no row for a `SubagentStop` whose agent type is empty or absent. Every dispatched agent, `general-purpose` included, carries a type and a Start; these are the harness's own side agents.
- `log-subagent` records each typed Start's time at `<state>/subagents/<session>/<agent>.start`, and a Stop without a payload `durationMs` takes the elapsed time from it, then removes it.
- An env-switch `used` bypass row is written once per session, hook, and mechanism, claimed with an exclusive create at `<state>/bypass/<session>/<hook>--<mechanism>`. A claim that fails for any reason other than "already claimed" still writes the row. Dismissals, `armed` rows, the global gates, and a session id unsafe in a path are never deduped.
- `log-session` removes the session's `subagents/` and `bypass/` state at `SessionEnd`.

## Impact

- Code: `crates/metrics/src/log_subagent.rs`, `log_bypass.rs`, `log_session.rs`.
- The SessionStart "N bypass(es) used" line now counts first uses per session, not every allowed call.
- A session that never reaches `SessionEnd` leaves its two small state dirs; the age sweep in cameronsjo/cadence-hooks#1590 removes them.
