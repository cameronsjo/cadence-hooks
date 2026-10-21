## MODIFIED Requirements

### Requirement: Protected branches
`git-safety` SHALL treat `main` and `master` as protected and block: a force push naming a protected destination; a `+` refspec to a protected branch; a force push of bare `HEAD` while on a protected branch or when git cannot name the branch; deleting a protected branch by `git push --delete`, a `:main` refspec, `git branch -d`/`-D` or `git update-ref -d`; and repointing a protected ref with `git update-ref`. A `git rebase` naming a protected branch MUST NOT block.

#### Scenario: Force push to main
- **WHEN** a Bash command is `git push --force origin main`
- **THEN** the hook exits 2 naming a force push to a protected branch

#### Scenario: Restacking onto main
- **WHEN** a Bash command is `git rebase --onto main old-base feature`
- **THEN** the command is not blocked

#### Scenario: Force push of the rebased branch
- **WHEN** a Bash command is `git rebase main && git push --force origin main`
- **THEN** the hook exits 2 naming a force push to a protected branch

### Requirement: Milder history edits nudge
`git-safety` SHALL nudge (exit 0 with a message beginning `Git operation may modify history or lose work:`) when no segment blocks and some segment runs: `git reset` without `--hard`; any `git rebase`; `git commit --amend`; `git stash drop` or `clear`; `git branch -d` of a non-protected branch; `git remote remove`/`rm`; `git restore` or `git checkout -- <named paths>` that overwrite local edits; `git update-ref -d` of a non-protected ref; or `git update-ref --stdin`.

#### Scenario: Soft reset
- **WHEN** a Bash command is `git reset HEAD~1`
- **THEN** the hook exits 0 with the history nudge

#### Scenario: Named-path checkout
- **WHEN** a Bash command is `git checkout -- src/lib.rs`
- **THEN** the hook exits 0 with the history nudge, not a block

#### Scenario: Rebase naming a protected branch
- **WHEN** a Bash command is `git rebase -i main`
- **THEN** the hook exits 0 with the history nudge, not a block

## ADDED Requirements

### Requirement: A rebase nudge names the way back
When a segment runs `git rebase`, the history nudge SHALL add a line telling the agent to run `git reflog` to find the commit from before the rebase. A nudge with no rebase segment MUST NOT carry that line.

#### Scenario: Rebase onto main
- **WHEN** a Bash command is `git rebase main`
- **THEN** the hook exits 0 with the history nudge and a line naming `git reflog`

#### Scenario: Amend
- **WHEN** a Bash command is `git commit --amend`
- **THEN** the hook exits 0 with the history nudge and no `git reflog` line
