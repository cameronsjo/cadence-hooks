## Why

gh takes the repo and host from a PR or issue URL argument before `-R`, `GH_REPO` and the checkout. `guard-gh-write` never read that argument, so `gh pr merge https://github.com/work-org/x/pull/1 --squash` was allowed from an owned checkout, or from anywhere with an owned `-R`, and merged in `work-org/x`. That is a write to a repo the operator does not own, the cadence-ecosystem ADR-0046 rule 2 harm. Reported in cameronsjo/cadence-hooks#1529.

## What Changes

- On the `gh pr` and `gh issue` write verbs that take a `<number> | <url> | <branch>` argument, a URL argument names the target, read as gh reads it: the repo and host from an `http`/`https` URL whose path starts `/OWNER/REPO/pull/N` (and `/issues/N` on the issue verbs and `gh pr lock|unlock`), skipping each verb's value flags as gh defines them. It wins over `-R`, `GH_REPO` and the checkout, as in gh.
- An unowned URL blocks with the usual "you don't own" reason; the fix asks the user to run the command, since gh writes to the URL's repo whatever `-R` says, and names no target. An owned URL is allowed from any directory.
- A URL given as a flag's value (`--body`, `--duplicate-of`, `--parent`, `--attach`) is not read. The loop checks, the `inject-gh-write-context` nudge and the `gh issue transfer` destination are unchanged.

Surfaces: `guard-gh-write` (PreToolUse, Bash), its exit code (0 to 2 for an unowned URL argument, 2 to 0 for an owned one outside an owned checkout) and its block payload's `fix`. No hooks.json change in cameronsjo/cadence.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: "gh write to a repository the operator does not own" lists a PR or issue URL argument among its sources, and a new requirement says it is read first.

## Impact

`crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `CHANGELOG.md`.
