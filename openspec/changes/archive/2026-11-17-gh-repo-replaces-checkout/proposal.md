## Why

When a `GH_REPO` is in force for a command gh reads it for, gh writes to the repository it names, not to one the checkout's remotes name (`gh pr create` still reads the remotes to find the head branch, but creates the PR on the `GH_REPO` repository). `guard-gh-write` still judged the checkout as a second candidate, so a write whose real target is owned blocked when it ran from inside a checkout of a repository the operator does not own: `GH_REPO=cameronsjo/tool gh issue comment 1 --body hi` in a checkout of `evil/up`. That breaks the rule that an owned target is never blocked. The same held for `gh repo deploy-key`, `gh repo autolink`, and `gh api` placeholder endpoints. The owner decided on 2026-11-17 to stop judging the checkout there (cameronsjo/cadence-hooks#1642, "Decisions wanted", third item).

## What Changes

- When a `GH_REPO` gh reads is in force (inline, exported or the hook process's) and the guard read every value in force exactly, the checkout's remotes are no target: not as the fallback, and not to fill a `repos/{owner}/{repo}` or `repos/:owner/:repo` placeholder.
- An exported or inherited `GH_REPO` replaces the checkout only when the command certainly hands it to gh: nothing in the command clears it (`unset GH_REPO` in any shell or compound command, `export -n GH_REPO`, `env -u GH_REPO`, `env -i`) and no export of it sits behind `&&` or `||`. Where either appears the checkout stays a target beside it, as before. An inline `GH_REPO=` on the gh word is always certain.
- The `orgs/{owner}/…` placeholder keeps its own rule from cameronsjo/cadence-hooks#1641 (any `GH_REPO` in force names the org); it is not changed here.
- The commands this applies to are the ones the guard already judges `GH_REPO` on: every `-R` write outside the `gh repo` and `gh gist` groups, `gh repo rename|deploy-key|autolink`, and a `gh api` endpoint with a placeholder. Every other command keeps today's judgment.
- Unchanged: an unowned `GH_REPO` blocks from any checkout; a `GH_REPO` the guard cannot read exactly (an expansion in it) keeps the checkout beside it, as before; `-R`, a PR or issue URL, a `gh repo` positional and a literal `gh api` owner are judged as before.
- MODIFY "Deploy-key and autolink writes" and ADD "GH_REPO replaces the checkout" in `repo-ownership`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: one requirement modified, one added.

## Impact

- `cadence-hooks guardrails guard-gh-write` (PreToolUse, Bash): a write under an owned `GH_REPO` from an unowned checkout or fork now allows. No verdict moves from allow to block.
- `crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `CHANGELOG.md`.
- No hooks.json change in cameronsjo/cadence.
