## MODIFIED Requirements

### Requirement: gh write to a repository the operator does not own
`guard-gh-write` (PreToolUse, Bash) SHALL block (exit 2, `gh write targets repo you don't own`) a `gh` write on a repository outside the allowlist, judging each segment of a chain on its own target. The target SHALL be read from a PR or issue URL argument, `-R`/`--repo`, a `GH_REPO` assignment, a `gh repo` verb's positional `owner/repo`, a `gh api repos/<owner>/<repo>/...` path, and otherwise the git remotes of the directory the segment runs in. Reads SHALL be allowed whatever the target.

#### Scenario: Ordinary write with an owned target
- **WHEN** the command is `gh pr create -R cameronsjo/tool --title t --body-file b.md` and `cameronsjo` is allowed
- **THEN** the hook allows

#### Scenario: Unowned write after an owned one
- **WHEN** the command is `gh issue comment 1 -R cameronsjo/tool --body ok && gh issue comment 2 -R evil/repo --body x`
- **THEN** the hook exits 2 naming `evil/repo` and the allowed entries

#### Scenario: Read on an unowned repo
- **WHEN** the command is `gh pr view 5 -R someone/else` or `gh repo clone someone/else`
- **THEN** the hook allows

## ADDED Requirements

### Requirement: gh write named by a PR or issue URL argument
On a `gh pr` or `gh issue` write verb that takes a `<number> | <url> | <branch>` argument, `guard-gh-write` SHALL judge the repo and host that a PR or issue URL in that argument names, read as gh reads it, before `-R`, `GH_REPO` and the checkout, and under `gh issue transfer` as well as them. An unowned one SHALL block with a fix that names no target. A URL given as a flag's value SHALL NOT count.

#### Scenario: Unowned PR URL past an owned target
- **WHEN** the command is `gh pr merge https://github.com/evil/repo/pull/1 --squash -R cameronsjo/tool`, in a checkout of `cameronsjo/tool`
- **THEN** the hook exits 2 naming `github.com/evil/repo`, and the fix asks the user to run the command and names no `cameronsjo/` repo

#### Scenario: Owned issue URL outside an owned checkout
- **WHEN** the command is `gh issue close https://github.com/cameronsjo/tool/issues/3`, in a checkout of `evil/repo` or in `/tmp`
- **THEN** the hook allows

#### Scenario: URL as a flag's value
- **WHEN** the command is `gh pr comment 5 --body https://github.com/evil/repo/pull/1`, in a checkout of `cameronsjo/tool`
- **THEN** the hook allows

#### Scenario: Owned issue URL in a transfer from an unowned checkout
- **WHEN** the command is `gh issue transfer https://github.com/cameronsjo/tool/issues/3 evil/repo`, in a checkout of `evil/repo`
- **THEN** the hook exits 2 naming `evil/repo`
