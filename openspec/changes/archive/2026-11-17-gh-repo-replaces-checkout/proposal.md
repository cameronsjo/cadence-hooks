## Why

When a `GH_REPO` is in force for a command gh reads it for, gh writes to the repository it names, not to one the checkout's remotes name (`gh pr create` still reads the remotes to find the head branch, but creates the PR on the `GH_REPO` repository). `guard-gh-write` still judged the checkout as a second candidate, so a write whose real target is owned blocked when it ran from inside a checkout of a repository the operator does not own: `GH_REPO=cameronsjo/tool gh issue comment 1 --body hi` in a checkout of `evil/up`. That breaks the rule that an owned target is never blocked. The same held for `gh repo deploy-key`, `gh repo autolink`, and `gh api` placeholder endpoints. The owner decided on 2026-11-17 to stop judging the checkout there (cameronsjo/cadence-hooks#1642, "Decisions wanted", third item).

## What Changes

- The checkout's remotes stop being a target (not the fallback, and not to fill a `repos/{owner}/{repo}` or `repos/:owner/:repo` placeholder) only when the guard can positively show that the `GH_REPO` it read exactly is the value gh receives. Three rules show it, and nothing else does:
  1. **Inline on gh.** Every word before the `gh` word is an assignment, and the last `GH_REPO=` there is a non-empty literal. A prefix on a wrapper (`sudo`, `env`, `bash -c`, …) does not count.
  2. **One plain export.** Outside the write's own text the command names `GH_REPO` exactly once, in a top-level `export GH_REPO=<literal>` before the write, joined to its neighbours by `;` or a newline, with no group, subshell, keyword or substitution opening before it; gh is the plain command word.
  3. **The hook process's value.** The command never names `GH_REPO`, and gh is a plain top-level command.
  In rules 2 and 3 the write's text occurs once in the command, no segment may source a script or run `eval` (also behind a keyword, group, `builtin` or `command`) or run `export`, `declare`, `typeset`, `local`, `readonly` or `unset` with an operand holding an expansion (`export $(cat .env | xargs)`), and the command may hold no here-document.
- Every other case keeps the checkout beside the `GH_REPO`, as on `main`. A list of ways to lose the variable is never complete (a plain reassignment of an exported one, `declare -x`, an export in a pipeline or the background, `sudo`, `source`), and keeping the checkout can only restore a block `main` already had.
- `gh secret` and `gh variable` `set` or `delete` with `--org`, and `gh issue transfer`, always keep the checkout: the guard does not read their real target, and on `main` the checkout is what blocks them.
- The `orgs/{owner}/…` placeholder keeps its own rule from cameronsjo/cadence-hooks#1641 (any `GH_REPO` in force names the org); it is not changed here.
- The commands this applies to are the ones the guard already judges `GH_REPO` on: every `-R` write outside the `gh repo` and `gh gist` groups, `gh repo rename|deploy-key|autolink`, and a `gh api` endpoint with a placeholder. Every other command keeps today's judgment.
- Unchanged: an unowned `GH_REPO` blocks from any checkout; a `GH_REPO` the guard cannot read exactly (an expansion in it) keeps the checkout beside it, as before; `-R`, a PR or issue URL, a `gh repo` positional and a literal `gh api` owner are judged as before.
- MODIFY "Deploy-key and autolink writes" and ADD "GH_REPO replaces the checkout" and "Writes past their repository keep the checkout" in `repo-ownership`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: one requirement modified, two added.

## Impact

- `cadence-hooks guardrails guard-gh-write` (PreToolUse, Bash): a write under an owned `GH_REPO` from an unowned checkout or fork now allows. No verdict moves from allow to block.
- `crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `CHANGELOG.md`.
- No hooks.json change in cameronsjo/cadence.
