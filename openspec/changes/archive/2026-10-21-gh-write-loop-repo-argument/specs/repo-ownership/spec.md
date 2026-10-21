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
