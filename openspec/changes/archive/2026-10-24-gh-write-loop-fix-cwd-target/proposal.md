## Why

A looped gh write with no `-R` blocks when the loop body changes directory, and always under `CADENCE_GH_STRICT_LOOPS=1`. The block's fix named the checkout's own repository whenever the checkout was owned. A body that changes directory writes to the repository it moves to, and a `gh api` path that names its own owner or repo is not the checkout's repository either. So `for d in a b; do (cd "$d" && gh release delete v1 --yes); done`, run from a checkout of `cameronsjo/tool`, got `Fix: add -R cameronsjo/tool to each command`, and applying it deletes `v1` from `cameronsjo/tool` twice (cameronsjo/cadence-hooks#1524).

## What Changes

- ADD "Loop fix targets": a loop block names the directory's repository only for a write gh sends there, a write with no `-R` in a body that stays in the directory or a `gh api` write whose path is `repos/{owner}/{repo}/…`. Every other write gets a placeholder.
- MODIFY "gh writes allowed without an ownership check": its strict-loops sentence points to the new requirement for the fix, instead of saying the resolved target is always suggested.

The verdicts do not change. Surfaces: `crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `CHANGELOG.md`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: one requirement added, one modified.

## Impact

`openspec/specs/repo-ownership/spec.md`, `crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `CHANGELOG.md`.
