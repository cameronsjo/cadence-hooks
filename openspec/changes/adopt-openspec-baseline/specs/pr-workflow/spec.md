## Purpose
PR workflow is the set of advisory hooks and the one CLI action that sit on a pull request's path from create to merge: the polish gate `cadence-hooks cadence nudge-polish-before-pr` and its marker writer `cadence-hooks cadence record-polish`, `cadence-hooks cadence warn-docs-update`, `cadence-hooks cadence warn-changelog-entry`, `cadence-hooks guardrails warn-pr-issue-link`, `cadence-hooks guardrails verify-pr-autoclose`, `cadence-hooks guardrails warn-gh-merge-preflight`, `cadence-hooks guardrails warn-unreviewed-ready-flip`, `cadence-hooks guardrails warn-stale-pr-body`, `cadence-hooks guardrails warn-stacked-base-delete` and `cadence-hooks guardrails nudge-upgrade-after-push`.

## ADDED Requirements

### Requirement: Advisory only
Every hook in this capability SHALL exit 0. None MUST block a command: each either stays silent or adds a nudge as additionalContext. A hook that cannot read what it needs (a failed `git` or `gh` call, a timeout, unparseable JSON, an unresolvable PR) SHALL stay silent rather than guess, except where a requirement below names a cannot-check nudge. Every hook in this capability SHALL honour `CADENCE_DISABLE` and `CADENCE_BYPASS=1`; none is protected.

#### Scenario: gh failure during a flip check
- **WHEN** `gh pr ready 5` runs and the hook's `gh` lookup of PR 5 fails
- **THEN** `warn-unreviewed-ready-flip` and `warn-stale-pr-body` exit 0 with no output

### Requirement: Polish ship anchors
`nudge-polish-before-pr` (PreToolUse, Bash) SHALL judge only a ship anchor: `gh pr ready`, a `gh pr create` without `--draft`/`-d`, or a bare `gh pr merge` naming no PR number, URL, branch, `-R`/`--repo` or `GH_REPO=`. Every other command SHALL be silent. Each anchor in a command SHALL be judged in the checkout that owns its branch, and the sharpest verdict SHALL win, so a polished first ship cannot vouch for a second.

#### Scenario: Draft create
- **WHEN** the command is `gh pr create --draft --title wip`
- **THEN** the hook exits 0 with no output

#### Scenario: Merge naming its PR
- **WHEN** the command is `gh pr merge 42 --squash`
- **THEN** `nudge-polish-before-pr` exits 0 with no output

### Requirement: Polish marker verdicts
`nudge-polish-before-pr` SHALL look up the polish marker for the anchor's repository and branch. It SHALL nudge with `No polish recorded for this branch` when no marker exists or the marker is older than 30 days (naming the expiry), and SHALL nudge on any branch when the marker's recorded change-set digest differs from a digest of the live working tree. A marker recording a dispositioned skip SHALL satisfy the gate and echo its reason. It MUST NOT compare commit SHAs.

#### Scenario: Unpolished ship
- **WHEN** `gh pr ready` runs on a branch with no polish marker
- **THEN** the hook exits 0 with a nudge starting `No polish recorded for this branch` that names `/polish` and the `record-polish` command

#### Scenario: Moved change set
- **WHEN** a marker was recorded and a later commit changed a code file on the branch
- **THEN** the hook nudges that the reviewed change set has moved and names `record-polish --fresh` or re-running `/polish`

### Requirement: Polish security-arm verdicts
When the branch's diff against `origin/main` touches code, `nudge-polish-before-pr` SHALL nudge, naming the gap, when the marker says the security arm was skipped (including a `docs`-scope pass), ran under a model family other than Opus, ran with no family attested, or when the marker records no arm roster. A current marker with none of these gaps SHALL allow silently. A branch that touches no code SHALL not draw these nudges.

#### Scenario: Polished ship
- **WHEN** `gh pr ready` runs on a code branch whose marker records `security=ran` by `opus` and whose digest matches the working tree
- **THEN** the hook exits 0 with no output

#### Scenario: Security arm skipped
- **WHEN** the marker records `security=skipped` and the branch diff touches code
- **THEN** the hook nudges that the SECURITY arm did not run and names `cadence-forge:security-reviewer`

#### Scenario: Wrong family
- **WHEN** the marker records `security=ran` with `--arm-model security=sonnet` on a code branch
- **THEN** the hook nudges that family `sonnet` does not satisfy the Opus-family requirement

### Requirement: Polish cannot-check and degraded states
`nudge-polish-before-pr` SHALL nudge with `Can't check polish for this PR` when the anchor names a repository that is not a remote of the checkout, a fork head, a head checked out nowhere, or conflicting heads, and when the cwd is in no repository; it MUST NOT give the clean allow in those cases. When the marker directory is not the private per-user one, it SHALL decide on marker presence alone, without reading the arm roster, and SHALL add a note naming the directory.

#### Scenario: Ship for another repository
- **WHEN** `gh pr create -R someone/other --title t` runs in a checkout with no remote for `someone/other`
- **THEN** the hook exits 0 with a `Can't check polish for this PR` nudge

### Requirement: Recording polish
`cadence-hooks cadence record-polish` is a CLI action, not a hook. It SHALL write a polish marker in the private marker directory (`CADENCE_MARKER_DIR` when set non-empty), keyed on the repository's shared git directory and the branch, so every worktree of the repository resolves it, and SHALL record a digest of the working tree's change set. It SHALL default to the current repository and branch, overridable with `--repo-root` and `--branch`.

#### Scenario: Record after a pass
- **WHEN** `cadence-hooks cadence record-polish --arm security=ran --arm-model security=opus` runs on branch `feat/x`
- **THEN** it exits 0 and a later `gh pr ready` on `feat/x` from any worktree of the repository is satisfied

#### Scenario: Detached HEAD
- **WHEN** `record-polish` runs with a detached HEAD and no `--branch`
- **THEN** it exits 1 and writes nothing

### Requirement: Polish record options and exit codes
`record-polish` SHALL accept `--scope full|code|docs`, repeatable `--arm NAME=STATE`, `--arm-model NAME=FAMILY` and `--arm-report NAME=PATH` (each only beside `--arm` for that name), `--fresh` to replace rather than merge the prior roster, and `--skip <reason>` alone. It MUST exit 0 when a marker was written, 1 when nothing was written, and 2 on a usage error. `CADENCE_DISABLE` MUST NOT affect it; under `CADENCE_BYPASS=1` it SHALL exit 0 writing nothing.

#### Scenario: Unknown scope
- **WHEN** `record-polish --scope everything` runs
- **THEN** it exits 2 and writes nothing

#### Scenario: Skip combined with arms
- **WHEN** `record-polish --skip "dnsmasq line only" --arm security=ran` runs
- **THEN** it exits 2 and writes nothing

### Requirement: Docs nudge
`warn-docs-update` (PreToolUse, Bash) SHALL nudge on `gh pr create` or `gh pr new` when the branch's diff against `origin/main` (else `origin/master`) changes a code file and none of `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md` or `docs/`, listing the doc files to review and noting dependency-manifest and public-API changes. A branch with no code change, or with a doc change, SHALL be silent.

#### Scenario: Code without docs
- **WHEN** `gh pr create --title t` runs and the branch changed only `src/lib.rs`
- **THEN** `warn-docs-update` nudges with `code file(s) changed but no documentation updated`

### Requirement: Changelog nudge
`warn-changelog-entry` (PreToolUse, Bash) SHALL nudge on the polish ship anchors when the branch's diff leaves an owed changelog untouched. When any `plugins/*/CHANGELOG.md` is tracked at the merge base, each plugin with a changed file owes its own one and a root edit MUST NOT satisfy it; changes directly under `plugins/<name>/docs/` or `scripts/` MUST NOT count. Otherwise a tracked root `CHANGELOG.md` is owed for any change. No tracked changelog, or an empty diff, SHALL be silent.

#### Scenario: Monorepo plugin change
- **WHEN** `gh pr ready` runs, the repo tracks `plugins/a/CHANGELOG.md`, and the branch changed `plugins/a/skills/s/SKILL.md` and the root `CHANGELOG.md` only
- **THEN** `warn-changelog-entry` nudges naming `plugins/a/CHANGELOG.md`

#### Scenario: Repository with no changelog
- **WHEN** `gh pr ready` runs in a repository that tracks no `CHANGELOG.md` anywhere
- **THEN** `warn-changelog-entry` exits 0 with no output

### Requirement: Closing keyword reminder
`warn-pr-issue-link` (PreToolUse, Bash) SHALL nudge on `gh pr create` when neither the command text nor the `--body-file`/`-F` file's contents hold a closing keyword (`close`, `closes`, `closed`, `fix`, `fixes`, `fixed`, `resolve`, `resolves`, `resolved`, any case) followed by an issue reference. A keyword inside a larger word (`discloses #2`) MUST NOT count. An unreadable body file SHALL be silent. The nudge SHALL say that a PR with no issue can carry on.

#### Scenario: Linked PR
- **WHEN** the command is `gh pr create --title x --body "Closes #12"`
- **THEN** the hook exits 0 with no output

#### Scenario: Unlinked PR
- **WHEN** the command is `gh pr create --title x --body "no link here"`
- **THEN** the hook nudges `PR body has no closing keyword`

### Requirement: Auto-close verification and straggler close
`verify-pr-autoclose` (PostToolUse, Bash) SHALL, after `gh pr create`, read the PR at the URL gh printed and nudge when a closing reference names an issue that is CLOSED or unreadable. After `gh pr merge` of a PR GitHub reports MERGED within 10 minutes in `origin`'s repository, it SHALL wait up to `GH_AUTOCLOSE_WAIT_SECONDS` (default 10; early return after 2 s), close each referenced issue still OPEN with a comment citing the PR and commit, and nudge naming them.

#### Scenario: Straggler after merge
- **WHEN** `gh pr merge 7 --squash` succeeds, PR 7's body says `Closes #3`, and issue 3 is still OPEN after the wait
- **THEN** the hook closes issue 3 with the commit-citing comment and nudges `closed 1 straggler issue(s) for PR #7: #3`

#### Scenario: Failed merge
- **WHEN** `gh pr merge 7` ran but GitHub reports PR 7 as OPEN
- **THEN** the hook closes nothing and exits 0 with no output

### Requirement: Merge preflight checklist
`warn-gh-merge-preflight` (PreToolUse, Bash) SHALL nudge on every `gh pr merge` with a three-point checklist: check `isDraft` and run `gh pr ready` first, delete a worktree-checked-out branch remotely with `git push origin --delete <branch>` instead of `--delete-branch`, and verify `gh pr view <n> --json mergedAt,mergeCommit` before retrying a failed merge. It SHALL make no `git` or `gh` call and SHALL be silent on every other command, including `git merge`.

#### Scenario: Any merge
- **WHEN** the command is `gh pr merge 5 --squash --delete-branch`
- **THEN** the hook nudges with the `gh pr merge preflight` checklist

### Requirement: Unreviewed ready flip
`warn-unreviewed-ready-flip` (PreToolUse, Bash) SHALL nudge on `gh pr ready` or `gh pr merge` when the PR head has no reviewed signal: an APPROVED review on that head by a human other than the author, or a review whose first line, untrimmed, is `<!-- cadence-review: <reviewer> head=<40-hex SHA> crit=0 imp=0 -->` naming the current head. It SHALL also nudge when a reviewer's latest decisive review is CHANGES_REQUESTED, naming the dismissal command.

#### Scenario: Clean marker at head
- **WHEN** `gh pr ready 5` runs and a review on PR 5 has first line `<!-- cadence-review: code-reviewer head=<current head> crit=0 imp=0 -->`
- **THEN** the hook exits 0 with no output

#### Scenario: Marker for an older head
- **WHEN** the only clean marker names a SHA that is not PR 5's current head
- **THEN** the hook nudges `PR #5 is not reviewed at head <short sha>`

### Requirement: Flip PR resolution
The flip checks (`warn-unreviewed-ready-flip`, `warn-stale-pr-body`) SHALL resolve the PR as gh would: a URL, a number with `-R` or in the cwd's repository, or a branch or no selector through `gh pr view`. They MUST NOT send a request to a host other than `github.com` or `origin`'s host, and SHALL stay silent for such a host, a repo flag with no selector, conflicting repo values or an unreadable selector. The unreviewed nudge SHALL say a marker posted earlier in the same command is not seen.

#### Scenario: Enterprise host named in the command
- **WHEN** the command is `gh pr ready https://ghe.example.com/o/r/pull/5` and `origin` is on `github.com`
- **THEN** both flip checks exit 0 with no output and make no request

### Requirement: Misplaced review marker
`warn-unreviewed-ready-flip` SHALL nudge on `gh pr review` when its inline `--body` or on-disk `--body-file` carries `head=<40 hex>`, `crit=` and `imp=` but its first line is not a well-formed `cadence-review` marker, giving the marker line to paste prefilled with the body's own head and counts. It MUST NOT call `gh` for this check and SHALL be silent when the first line already parses or the body cannot be read.

#### Scenario: Marker values in the summary
- **WHEN** the command is `gh pr review 3 --comment --body "summary: head=<40 hex> crit=1 imp=0"`
- **THEN** the hook nudges with `<!-- cadence-review: <reviewer> head=<40 hex> crit=1 imp=0 -->` to place on the first line

### Requirement: Stale PR body at the flip
`warn-stale-pr-body` (PreToolUse, Bash) SHALL nudge on `gh pr ready` or `gh pr merge` when GitHub reports the PR body was never edited after creation (a title edit does not count) and at least one commit on the PR has a committer date after the PR was opened, naming the commit count and `gh pr edit <n> --body-file <file>`. It SHALL resolve the PR exactly as `warn-unreviewed-ready-flip` does, with the same host restriction.

#### Scenario: Placeholder body
- **WHEN** `gh pr ready 9` runs, PR 9's body was never edited, and 3 commits were made after it was opened
- **THEN** the hook nudges that the body has not been edited and the branch has gained 3 commits

#### Scenario: Refreshed body
- **WHEN** PR 9's body was edited after it was opened
- **THEN** the hook exits 0 with no output

### Requirement: Deleting a stacked base
`warn-stacked-base-delete` (PreToolUse, Bash) SHALL nudge before `git push <remote> --delete <branch>` (or `-d`, or `:<branch>`) and `gh pr merge --delete-branch`/`-d` when open PRs use the deleted branch as their base, naming them and `gh pr edit <n> --base <new-base>`. A fork PR's merge, and a remote not on `github.com` or `origin`'s host, SHALL be silent. More than 8 deleted branches SHALL nudge unchecked.

#### Scenario: Base of an open PR
- **WHEN** `git push origin --delete feat/base` runs and open PR #12 bases on `feat/base`
- **THEN** the hook nudges `1 open PR (#12) bases on` `feat/base`

#### Scenario: Ordinary branch delete
- **WHEN** `git push origin --delete feat/done` runs and no open PR bases on it
- **THEN** the hook exits 0 with no output

### Requirement: Upgrade after a cadence-hooks release push
`nudge-upgrade-after-push` (PostToolUse, Bash) SHALL nudge, after a `git push` to `main` or `master` from a checkout whose `origin` is `cameronsjo/cadence-hooks`, to schedule a one-shot deferred Homebrew upgrade about four minutes out. A push mentioned in an `echo`, heredoc or commit message MUST NOT fire. Under `CLAUDE_CODE_REMOTE=true` it MUST exit 0 silently before reading input; every other hook here SHALL run unchanged there.

#### Scenario: Push to main
- **WHEN** `git push origin main` completes in a cadence-hooks checkout
- **THEN** the hook nudges `cadence-hooks was just pushed to main` with the CronCreate instruction

#### Scenario: Other repository
- **WHEN** `git push origin main` completes in a checkout whose origin is another repository
- **THEN** the hook exits 0 with no output
