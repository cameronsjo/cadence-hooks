## Why

`guard-push-remote` blocked `eval "$S"; git push origin feat` and the direnv line, `eval "$(direnv export bash)"; git push origin feat`, in an owned checkout: "Cannot tell which repository this push runs in". Its push walk refused any repository an `eval` might move the push to. The guard read the push exactly and blocked on the part it could not read. cadence-ecosystem ADR-0046 rule 3 says to judge what was read and allow the rest.

cameronsjo/cadence-hooks#1523 settled the same case for `guard-gh-write` with core's `UnreadEval::StaysPut`. This change asks for it in both of the push guard's walks (cameronsjo/cadence-hooks#1530).

## What Changes

- The push walk in core takes the same switch. Under `StaysPut`, an `eval` whose script needs expansion leaves the push where the walk read it. It still leaves the repository unknown when something read in it or in the command may move: its words name `cd`, `pushd`, `popd` or `eval`, or hold a backslash, a variable the command names, or an expansion other than a command substitution or a plain variable; or the command defines a function, or may replace a tool or point git elsewhere.
- `guard-push-remote` asks for `StaysPut` in the push walk and in the per-segment directory walk. Every other guard keeps its reading.
- An `eval` of text the walk can read still leaves the repository unknown, because the push walk does not follow its script.
- MODIFY "Push shapes the push guard refuses" to point at the new requirement for `eval`. ADD "Push after an eval of text built at run time".

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: one requirement modified, one added.

## Impact

- `cadence-hooks guardrails guard-push-remote` (PreToolUse, Bash): a push after such an `eval` exits 0 in an owned checkout, not 2. No message, env var, config key, ledger or marker file changes.
- `crates/core/src/push.rs`, `crates/core/src/shell.rs`, `crates/guardrails/src/guard_push_remote.rs`, `CHANGELOG.md`.
- No hooks.json change in cameronsjo/cadence.
