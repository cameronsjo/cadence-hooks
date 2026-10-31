## 1. Subagent rows

- [x] 1.1 Skip a `SubagentStop` with no agent type
- [x] 1.2 Fill `durationMs` from a Start marker when the payload has none, and consume the marker

## 2. Bypass rows

- [x] 2.1 Write an env-switch `used` row once per session, hook, and mechanism, through an exclusive-create claim that fails toward writing

## 3. Cleanup and tests

- [x] 3.1 Remove the session's `subagents/` and `bypass/` state at `SessionEnd`
- [x] 3.2 Stage the skip and the claim off once and confirm their tests go red
