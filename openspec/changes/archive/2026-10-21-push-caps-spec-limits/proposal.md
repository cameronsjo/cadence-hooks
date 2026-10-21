## Why

The third code review of cameronsjo/cadence-hooks#1479 found two gaps in "How many pushes the push guard checks". Each sentence there is true, but each leaves out a case. Probes against the built binary confirm both.

- The guard has a third cap the requirement does not name. Five remotes that `-c remote.pushDefault=`, `branch.<b>.pushRemote=` or `branch.<b>.remote=` (or an earlier config write) point a command's pushes at exit 2 with `too many push remotes to verify`. Four pass.
- The literal `git -C` loop reader refuses a command over 4096 bytes and one that does not begin with `for`. So the requirement's own five-remote loop exits 2 with `too many push-loop remotes to verify` when a `# push all` line comes before it, or when a trailing comment takes it past 4 KB. A comment after the loop on the same line still passes.

Part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443).

## What Changes

- MODIFY "How many pushes the push guard checks": name the config-named remote cap, and say the literal loop must be under 4 KB and begin with `for`. Its three scenarios stay, and two are added.
- Pin both in tests: five config-named remotes block and four pass; the loop reader refuses a leading comment, a leading command and a command over 4 KB, and reads one with a trailing comment.

No verdict changes. Surfaces: `openspec/specs/repo-ownership/spec.md` and two tests.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: one requirement modified.

## Impact

`openspec/specs/repo-ownership/spec.md`, `crates/guardrails/src/guard_push_remote.rs` (test), `crates/core/src/loop_analysis.rs` (test).
