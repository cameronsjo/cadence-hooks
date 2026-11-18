## Why

When a `GH_REPO` is in force for a command gh reads it for, gh writes to the repository it names, not to one the checkout's remotes name (`gh pr create` still reads the remotes to find the head branch, but creates the PR on the `GH_REPO` repository). `guard-gh-write` still judged the checkout as a second candidate, so a write whose real target is owned blocked when it ran from inside a checkout of a repository the operator does not own: `GH_REPO=cameronsjo/tool gh issue comment 1 --body hi` in a checkout of `evil/up`. That breaks the rule that an owned target is never blocked. The same held for `gh repo deploy-key`, `gh repo autolink`, and `gh api` placeholder endpoints. The owner decided on 2026-11-17 to stop judging the checkout there (cameronsjo/cadence-hooks#1642, "Decisions wanted", third item).

## What Changes

- The checkout's remotes stop being a target (not the fallback, and not to fill a `repos/{owner}/{repo}` or `repos/:owner/:repo` placeholder) only for three exact shapes, with the `GH_REPO` read exactly. No other shape replaces the checkout:
  1. **Inline on gh.** Every word before the `gh` word is an assignment, and the last `GH_REPO=` there is a non-empty literal. This holds whatever else the command contains, because the inline assignment is what that process receives. A prefix on a wrapper (`sudo`, `env`, `bash -c`, …) does not count.
  2. **One export, then only gh.** The whole command is one top-level `export GH_REPO=<literal>`, then `;` or a newline, then one or more plain gh invocations (each optionally with inline assignment prefixes) joined by `;`, a newline, `&&` or `||`.
  3. **Only gh, under the hook process's value.** The whole command is plain gh invocations as in rule 2, and it never names `GH_REPO`. It is an accepted assumption that the hook process's `GH_REPO` is the one the command's shell hands gh.

  Rules 2 and 3 hold nothing else, anywhere, gh's own arguments included: no other command word, substitution, backtick, subshell, group, function, keyword, process substitution or here-document. gh's literal placeholders `{owner}`, `{repo}` and `{branch}` are not groups. All three rules refuse when the command names `GH_HOST` outside an inline prefix on the gh invocation being judged, because an exported `GH_HOST` moves a bare `GH_REPO` to a host the guard does not judge.
- Every other command keeps the checkout beside the `GH_REPO`, as on `main`. This includes `cd x && gh …` and a command substitution in an argument under rules 2 and 3. Some of the relaxation is given up on purpose: a list of what another segment could do to the environment is never complete, and keeping the checkout can only restore a block `main` already had.
- `gh secret` and `gh variable` `set` or `delete` with `--org`, and `gh issue transfer`, always keep the checkout: the guard does not read their real target, and on `main` the checkout is what blocks them.
- The `orgs/{owner}/…` placeholder keeps its own rule from cameronsjo/cadence-hooks#1641 (any `GH_REPO` in force names the org); it is not changed here.
- The commands this applies to are the ones the guard already judges `GH_REPO` on: every `-R` write outside the `gh repo` and `gh gist` groups, `gh repo rename|deploy-key|autolink`, and a `gh api` endpoint with a placeholder. Every other command keeps today's judgment.
- Unchanged: an unowned `GH_REPO` blocks from any checkout; a `GH_REPO` the guard cannot read exactly (an expansion in it) keeps the checkout beside it, as before; `-R`, a PR or issue URL, a `gh repo` positional and a literal `gh api` owner are judged as before.
- MODIFY "Deploy-key and autolink writes" and ADD "GH_REPO replaces the checkout", "The hook process's GH_REPO is the command shell's" and "Writes past their repository keep the checkout" in `repo-ownership`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: one requirement modified, three added.

## Impact

- `cadence-hooks guardrails guard-gh-write` (PreToolUse, Bash): a write under an owned `GH_REPO` from an unowned checkout or fork now allows. No verdict moves from allow to block.
- `crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `CHANGELOG.md`.
- No hooks.json change in cameronsjo/cadence.
