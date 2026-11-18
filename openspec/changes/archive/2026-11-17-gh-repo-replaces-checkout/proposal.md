## Why

When a `GH_REPO` is in force for a command gh reads it for, gh writes to the repository it names, not to one the checkout's remotes name (`gh pr create` still reads the remotes to find the head branch, but creates the PR on the `GH_REPO` repository). `guard-gh-write` still judged the checkout as a second candidate, so a write whose real target is owned blocked when it ran from inside a checkout of a repository the operator does not own: `GH_REPO=cameronsjo/tool gh issue comment 1 --body hi` in a checkout of `evil/up`. That breaks the rule that an owned target is never blocked. The same held for `gh repo deploy-key`, `gh repo autolink`, and `gh api` placeholder endpoints. The owner decided on 2026-11-17 to stop judging the checkout there (cameronsjo/cadence-hooks#1642, "Decisions wanted", third item).

## What Changes

Two behaviors change: the checkout is replaced as a target for three exact shapes (below), and a placeholder filled from `GH_REPO` is judged on the host gh sends the write to (last bullet of this list). The second also moves a verdict outside the three shapes.

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
- A `gh api` `repos/{owner}/…` placeholder filled from `GH_REPO` is judged on the endpoint URL's host, else the command's host (`--hostname`, else `GH_HOST`, else the default host), and never on a host the `GH_REPO` value names. gh 2.104.0's `fillPlaceholders` in `pkg/cmd/api/api.go` takes only `RepoOwner()` and `RepoName()` from the base repository, and `gh api` sends the request to `--hostname`, else the default host. This holds whether or not a shape above applies, so it moves one verdict outside them: `GH_REPO=<extra-host>/<owned-owner>/tool gh api -X POST repos/{owner}/{repo}/issues …` blocked on `main` (judged on the extra host) and allows now (gh writes to the owned repo on the default host), from an owned checkout too. The converse, a placeholder sent to an unowned host by an absolute URL or `--hostname`, blocks.
- MODIFY "Deploy-key and autolink writes" and ADD "GH_REPO replaces the checkout", "The hook process's GH_REPO is the command shell's", "Writes past their repository keep the checkout" and "A GH_REPO-filled placeholder is judged on the host gh sends it to" in `repo-ownership`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `repo-ownership`: one requirement modified, four added.

## Impact

- `cadence-hooks guardrails guard-gh-write` (PreToolUse, Bash): a write under an owned `GH_REPO` from an unowned checkout or fork now allows in the three shapes, and a placeholder write under a host-qualified owned `GH_REPO` allows where gh sends it to the owned repo. One known verdict moves from allow to block: the guard's default host is `GH_HOST`, else github.com, while gh's is `GH_HOST`, else the only logged-in host. So on a GHE-only login with no `GH_HOST`, a placeholder filled from a host-qualified owned `GH_REPO` (`GH_REPO=ghe.work.com/cameronsjo/tool gh api … repos/{owner}/{repo}/…` from a checkout of that repo) is judged on github.com and blocks, where `main` allowed it through the checkout. This is recorded on the tracking issue, not fixed here.
- `crates/guardrails/src/guard_gh_write.rs`, `docs/configuration.md`, `CHANGELOG.md`.
- No hooks.json change in cameronsjo/cadence.
