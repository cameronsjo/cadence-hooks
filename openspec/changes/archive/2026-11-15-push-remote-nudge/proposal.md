## Why

cadence-ecosystem ADR-0046 phase 2 says `guard-push-remote` becomes a nudge until phase 3's `pre-push` hook replaces it (cameronsjo/cadence-hooks#1443). The guard still blocked: a push to an unowned remote, and also any push whose target, directory or loop it could not read, including when its own git probe timed out ("failing closed"). Rule 3 of the ADR says uncertain means allow, and a nudge must name a concrete action. The ADR accepts the gap in "What is given up": from phase 2 until phase 3, a `git push` to a remote the operator does not own only nudges.

## What Changes

- `guard-push-remote` never blocks. When it reads a push's remote exactly (a literal URL, a remote name git resolves, or a bare push's tracking remote, in a directory the push walk followed) and the remote's owner is not on the allowlist, it nudges, naming the remote and the action: confirm the remote, or push to the fork.
- Everything else allows with no output: a variable or substitution, an unfollowed `cd` or `git -C "$X"`, an `eval` that may move, a `GIT_DIR`/`--git-dir` redirect, a `-c` override, a bare push after a possible branch switch, a URL with no `owner/repo`, a remote git cannot resolve, a probe timeout, more than four distinct remotes, and an unset allowlist.
- The chain, loop, literal-loop, unparsed-command and directory-check arms, and the guard's own tests for them, are deleted.
- The guard leaves the security-critical and protected sets: a payload it cannot parse no longer blocks it, and `CADENCE_DISABLE` can switch it off.
- REMOVE the requirements for the shapes the guard refused, its loop and probe caps, literal `git -C` loops, run-time targets and the unparsed-command nudges. MODIFY the allowlist, push, configuration, eval and protected-guard requirements. ADD "Pushes the push guard does not judge".

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: five requirements modified, seven removed, one added.
- `configuration`: "Unset owner allowlist" modified.
- `hook-protocol`: "Selective disable" modified.

## Impact

- `cadence-hooks guardrails guard-push-remote` (PreToolUse, Bash): exit 0 on every input. A push to an unowned remote it read exactly gets a nudge (`Push target is not on your allowlist`); every former block message is gone.
- `manifest`: the guard's `criticality` is `workflow` and `protected` is `false`.
- `crates/guardrails/src/guard_push_remote.rs`, `src/registry.rs`, `crates/core/src/bypass.rs`, `tests/`, `docs/hooks.md`, `docs/testing.md`, the `developing-guards` repo skill, `CHANGELOG.md`.
- No hooks.json change in cameronsjo/cadence.
