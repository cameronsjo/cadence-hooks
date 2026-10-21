## Why

The third code review of cameronsjo/cadence-hooks#1479 found two gaps in "How many pushes the push guard checks". Each sentence there is true, but each leaves out a case. Probes against the built binary confirm both.

- The guard has a third cap the requirement does not name. Over four directory and remote pairs that `-c remote.pushDefault=`, `branch.<b>.pushRemote=` or `branch.<b>.remote=` (or an earlier config write) point a command's pushes at exit 2 with `too many push remotes to verify`. Four pass. The cap counts pairs, so one remote named in five `git -C` directories blocks too.
- The literal `git -C` loop reader refuses a command over 4096 bytes (4096 reads) and one that does not begin with `for`. So the requirement's own five-remote loop exits 2 with `too many push-loop remotes to verify` when a `# push all` line comes before it, or when a trailing comment takes it past 4 KB. A comment after the loop on the same line still passes.

Part of the phase 2 guard narrowing (cameronsjo/cadence-hooks#1443).

## What Changes

- MODIFY "How many pushes the push guard checks": name the config cap, which counts directory and remote pairs, and point the literal loop at its own requirement. Its first two scenarios stay, and "Five config-named remotes" is added.
- ADD "Literal `git -C` push loops": the loop must be at most 4096 bytes, begin with `for` and be one loop. It takes the "Five remotes in a literal `git -C` loop" scenario, and adds "Comment before a literal loop".
- Pin both in tests: five config-named remotes block and four pass; the loop reader reads a 4096-byte command and refuses a 4097-byte one, a leading comment and a leading command; at the hook, a comment before the scenario's loop blocks with `too many push-loop remotes to verify`.

No verdict changes. Surfaces: `openspec/specs/repo-ownership/spec.md` and three tests.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: one requirement modified, one added.

## Impact

`openspec/specs/repo-ownership/spec.md`, `crates/guardrails/src/guard_push_remote.rs` (test), `crates/core/src/loop_analysis.rs` (test).
