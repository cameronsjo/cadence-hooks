## MODIFIED Requirements

### Requirement: gh writes allowed without an ownership check
`guard-gh-write` SHALL allow `gh gist` writes and `gh repo fork` (they land under the operator's account) and `gh issue create --web`/`-w` unless the command sets `BROWSER=` or `GH_BROWSER=`. A loop of writes that name no target SHALL be allowed when its body never changes directory and the directory resolves to an owned non-fork repository; with `CADENCE_GH_STRICT_LOOPS=1` it MUST block and suggest the resolved target. An ownership probe past the git-probe deadline MUST allow.

#### Scenario: Gist from an unowned checkout
- **WHEN** `gh gist create notes.md` runs in a checkout whose remote is unowned
- **THEN** the hook allows

#### Scenario: Strict loops
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `for n in 1 2; do gh issue close $n; done` in an owned checkout
- **THEN** the hook exits 2 and the reason suggests the resolved `-R owner/repo`

### Requirement: gh writes in a loop the parser reads
In a loop the loop parser reads, `guard-gh-write` MUST block a gh write that names no target when the loop body changes directory or the directory does not resolve to an owned non-fork repository. A write names its target with `-R`, or for `gh repo archive`, `delete`, `edit` and `create`, which take no `-R`, with a repository argument whose owner is spelled out. The reason SHALL name `-R` as the fix, or that argument for those verbs.

#### Scenario: Loop that changes directory
- **WHEN** the command is `for d in a b; do cd $d; gh issue close 1; done` in an owned checkout
- **THEN** the hook exits 2 and the reason tells the operator to add `-R`

#### Scenario: Loop in an unowned checkout
- **WHEN** the command is `for n in 1 2; do gh issue close $n; done` in a checkout whose remote is unowned
- **THEN** the hook exits 2

#### Scenario: Loop of repo archives under an allowed owner
- **WHEN** the command is `for r in a b; do gh repo archive "cameronsjo/$r" --yes; done` in a directory with no git remote
- **THEN** the hook allows

#### Scenario: Loop of repo archives that changes directory
- **WHEN** `CADENCE_GH_STRICT_LOOPS=1` and the command is `for d in a b; do cd "$d"; gh repo archive "cameronsjo/$d" --yes; done`
- **THEN** the hook allows, because the argument names the target wherever the loop runs

#### Scenario: Loop of repo archives under an unowned owner
- **WHEN** the command is `for r in a b; do gh repo archive "evil/$r" --yes; done`, in any directory
- **THEN** the hook exits 2, because the per-segment check judges the owner `evil`

#### Scenario: Loop of repo archives with a variable owner
- **WHEN** the command is `for r in a b; do gh repo archive "$o/$r" --yes; done` in a directory with no git remote
- **THEN** the hook exits 2 and the reason names the repository argument (`gh repo archive owner/<repo>`), not `-R`

#### Scenario: Loop of repo creates from an owned template
- **WHEN** the command is `for r in a b; do gh repo create --template cameronsjo/tpl "work-org/$r" --private; done` in a directory with no git remote
- **THEN** the hook exits 2, because the template is not the target and the new repository's owner `work-org` is not allowed

### Requirement: gh write to a repository the operator does not own
`guard-gh-write` (PreToolUse, Bash) SHALL block (exit 2, `gh write targets repo you don't own`) a `gh` write on a repository outside the allowlist, judging each segment of a chain on its own target. The target SHALL be read from `-R`/`--repo`, a `GH_REPO` assignment, a `gh repo` verb's positional `owner/repo`, a `gh api repos/<owner>/<repo>/...` path, and otherwise the git remotes of the directory the segment runs in. Reads SHALL be allowed whatever the target.

#### Scenario: Ordinary write with an owned target
- **WHEN** the command is `gh pr create -R cameronsjo/tool --title t --body-file b.md` and `cameronsjo` is allowed
- **THEN** the hook allows

#### Scenario: Unowned write after an owned one
- **WHEN** the command is `gh issue comment 1 -R cameronsjo/tool --body ok && gh issue comment 2 -R evil/repo --body x`
- **THEN** the hook exits 2 naming `evil/repo` and the allowed entries

#### Scenario: Read on an unowned repo
- **WHEN** the command is `gh pr view 5 -R someone/else` or `gh repo clone someone/else`
- **THEN** the hook allows

#### Scenario: Repo created from an owned template
- **WHEN** the command is `gh repo create --template cameronsjo/tpl work-org/x --private`
- **THEN** the hook exits 2 naming `work-org/x`, because under `gh repo create` `--template` and `-p` take the template as their value and the argument is the new repository
