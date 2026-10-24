## Why

A looped gh write with no `-R` blocks when the loop body changes directory, and always under `CADENCE_GH_STRICT_LOOPS=1`. The block's fix named the checkout's own repository whenever the checkout was owned. A body that changes directory writes to the repository it moves to, and a `gh api` path that names its own owner or repo is not the checkout's repository either. So `for d in a b; do (cd "$d" && gh release delete v1 --yes); done`, run from a checkout of `cameronsjo/tool`, got `Fix: add -R cameronsjo/tool to each command`, and applying it deletes `v1` from `cameronsjo/tool` twice (cameronsjo/cadence-hooks#1524). Under `CADENCE_GH_STRICT_LOOPS=1` the same held for a body that stays put while gh sends its writes elsewhere: under a `GH_REPO`, or after a `cd` before the loop that the whole-command scan does not read, such as one in a subshell (review of #1548).

## What Changes

- ADD "Loop fix targets": a loop block names the directory's repository only when gh sends every looped write there: the body stays in the directory, every gh command runs there when each segment is followed on its own (a `cd` in a subshell, a group, an `if` or on a later line, or a `pushd`, moves it), no `GH_REPO`, `GH_HOST` or `GIT_DIR` is named or inherited, and a `gh api` write's path is `repos/{owner}/{repo}/…`. Every other fix gets a placeholder.
- MODIFY "gh writes allowed without an ownership check": its strict-loops sentence points to the new requirement for the fix, instead of saying the resolved target is always suggested.

The verdicts do not change. Surfaces: `crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `CHANGELOG.md`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: one requirement added, one modified.

## Impact

`openspec/specs/repo-ownership/spec.md`, `crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `CHANGELOG.md`.
