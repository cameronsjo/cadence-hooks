# git-safety Specification

## Purpose
Guards on Bash commands that run git: `cadence-hooks cadence git-safety` blocks git operations that destroy local work or rewrite a protected branch and nudges on milder history edits, while `cadence-hooks guardrails warn-amend-pushed`, `cadence-hooks guardrails warn-untracked` and `cadence-hooks guardrails warn-branch-base` are advisory nudges that never block.

## Requirements

### Requirement: Destructive git operations block
`git-safety` SHALL block (exit 2, stderr beginning `BLOCKED: git-safety: dangerous git operation` with a `Found:` line) a Bash command in which any segment runs: `git reset --hard`; `git clean` with `-f` or `--force`; `git checkout` or worktree-touching `git restore` of `.`, `./` or `:/`; `git reflog expire --expire=...`; `git gc --prune=now`; `git filter-branch` or `git filter-repo`; or `git push --mirror`.

#### Scenario: Reset hard
- **WHEN** a Bash command is `git reset --hard HEAD~1`
- **THEN** the hook exits 2 and stderr names `git reset --hard`

#### Scenario: Ordinary command is allowed
- **WHEN** a Bash command is `git status && git log --oneline -5`
- **THEN** the hook exits 0 with no message

### Requirement: Every segment is judged
`git-safety` SHALL judge each command segment on its own, so a destructive segment MUST block when it sits beside benign ones (`git status && git reset --hard`) or inside a subshell, group or `sh -c` wrapper the guard reads. Any blocking segment SHALL win over a nudging one.

#### Scenario: Shielded by a benign segment
- **WHEN** a Bash command is `git status && git clean -fd`
- **THEN** the hook exits 2

### Requirement: Protected branches
`git-safety` SHALL treat `main` and `master` as protected and block: a force push naming a protected destination; a `+` refspec to a protected branch; a force push of bare `HEAD` while on a protected branch or when git cannot name the branch; deleting a protected branch by `git push --delete`, a `:main` refspec, `git branch -d`/`-D` or `git update-ref -d`; repointing a protected ref with `git update-ref`; and `git rebase` naming a protected branch except as the `--onto` value.

#### Scenario: Force push to main
- **WHEN** a Bash command is `git push --force origin main`
- **THEN** the hook exits 2 naming a force push to a protected branch

#### Scenario: Restacking onto main
- **WHEN** a Bash command is `git rebase --onto main old-base feature`
- **THEN** the command is not blocked

### Requirement: Force push of other branches nudges
A force push (a force flag or a `+` refspec) to a branch other than `main` or `master` MUST NOT block; `git-safety` SHALL nudge instead.

#### Scenario: Force push of a feature branch
- **WHEN** a Bash command is `git push --force-with-lease origin feat/x`
- **THEN** the hook exits 0 with a nudge that the git operation may modify history

### Requirement: Milder history edits nudge
`git-safety` SHALL nudge (exit 0 with a message beginning `Git operation may modify history or lose work:`) when no segment blocks and some segment runs: `git reset` without `--hard`; `git rebase`; `git commit --amend`; `git stash drop` or `clear`; `git branch -d` of a non-protected branch; `git remote remove`/`rm`; `git restore` or `git checkout -- <named paths>` that overwrite local edits; `git update-ref -d` of a non-protected ref; or `git update-ref --stdin`.

#### Scenario: Soft reset
- **WHEN** a Bash command is `git reset HEAD~1`
- **THEN** the hook exits 0 with the history nudge

#### Scenario: Named-path checkout
- **WHEN** a Bash command is `git checkout -- src/lib.rs`
- **THEN** the hook exits 0 with the history nudge, not a block

### Requirement: Normalization before matching
`git-safety` SHALL match git commands after quote-aware tokenizing, lowercasing, removing shell backslash escapes, accepting a path to git (`/usr/bin/git`), and skipping global options between `git` and the subcommand (`-C <path>`, `-c <k>=<v>`, `--git-dir`, `--work-tree` and other dash options). A segment that defines a git alias (`git config alias.x ...`) SHALL be exempt, but a destructive sibling segment MUST still block.

#### Scenario: Global flags before the subcommand
- **WHEN** a Bash command is `git -C /repo -c core.pager=cat reset --hard`
- **THEN** the hook exits 2

#### Scenario: Quoted text is not a command
- **WHEN** a Bash command is `git commit -m "never run git reset --hard here"`
- **THEN** the command is not blocked

### Requirement: Judges what it read and allows the rest
Per ADR-0046, `git-safety` MUST NOT refuse a command because part of it could not be parsed (an oversized brace expansion, a `#` glued to a parenthesis, an unusual function header, a bash 5.3 `${ cmd; }`). It SHALL judge the segments it did read, so a readable destructive segment beside an unreadable shape still blocks.

#### Scenario: Padding does not refuse an ordinary command
- **WHEN** a Bash command is `echo {1..9999}; git status`
- **THEN** the hook does not block

### Requirement: Unseen execution nudges
When a command otherwise allows but runs text the guard cannot read (a script file that may run git, a sourced script, an `eval` of text built at run time, or a command named by a substitution), `git-safety` SHALL nudge with `git-safety cannot see inside ...` and MUST NOT block. A script file it reads whole that never names `git`, and known tool-init evals such as `eval "$(ssh-agent -s)"`, MUST draw no nudge.

#### Scenario: Runtime eval
- **WHEN** a Bash command is `eval "$CMD"`
- **THEN** the hook exits 0 with a nudge that git-safety cannot see inside an eval of text built at run time

### Requirement: Fail-open on its own failures
`git-safety` SHALL allow when the payload carries no Bash command. When resolving the current branch for a bare-`HEAD` force push times out under the hook deadline, it MUST NOT block on that basis and SHALL record a suppressed block instead. It is a protected guard: `CADENCE_DISABLE` naming it MUST NOT switch it off.

#### Scenario: Branch probe times out
- **WHEN** `git push --force origin HEAD` runs and the branch probe hits the deadline
- **THEN** the push is not blocked for an unresolved branch

### Requirement: Amend of a published commit
`warn-amend-pushed` SHALL nudge (exit 0, never block) when a segment runs `git commit --amend` in a repository whose remote-tracking refs already contain `HEAD`, naming those refs (sanitized) and suggesting a new commit instead. It MUST stay silent when no remote-tracking ref has the commit, and on every resolution failure (no repository, unborn `HEAD`, git missing, deadline).

#### Scenario: Amending a pushed commit
- **WHEN** `git commit --amend --no-edit` runs and `origin/feat` contains `HEAD`
- **THEN** the hook exits 0 with a nudge naming `origin/feat`

#### Scenario: Unpublished amend
- **WHEN** `git commit --amend` runs and no remote-tracking ref contains `HEAD`
- **THEN** the hook exits 0 with no message

### Requirement: Amend check follows only provable directories
`warn-amend-pushed` SHALL follow only a top-level `cd <dir>` joined by `&&`, `;` or a newline. It MUST stay silent when any other segment could move the directory (`pushd`, `eval`, `source`, a subshell, a non-git command), or the amend uses `--git-dir`, `--work-tree`, `GIT_DIR=` or `GIT_WORK_TREE=`.

#### Scenario: Directory moved by an unknown command
- **WHEN** a command runs `make prep && git commit --amend` on a published commit
- **THEN** the hook exits 0 with no message

### Requirement: Untracked files at commit
`warn-untracked` SHALL nudge (exit 0, never block) on a `git add` or `git commit` segment when the target repository has untracked, non-ignored files, listing up to 20 sanitized names and a count of the rest, and filtering build artifacts (`.log`, `.tmp`, `.cache`, `.pyc`, `.class`, `.o`, `.a`, `.so`, `.dylib`). Any git failure or unresolvable directory MUST yield silence.

#### Scenario: Forgotten file
- **WHEN** `git commit -m x` runs with an untracked `notes.md` at the repository root
- **THEN** the hook exits 0 with a nudge listing `?? notes.md`

#### Scenario: Only artifacts
- **WHEN** the only untracked file is `debug.log`
- **THEN** the hook exits 0 with no message

### Requirement: Untracked check runs safely in the right repo
`warn-untracked` SHALL judge the repository a leading unconditional `cd` moves into within the session's tree, and MUST run git there with `core.fsmonitor` and the untracked cache switched off. When a plain `git commit` takes only staged content and a plan under `docs/plans` is modified but unstaged in the session's own checkout, it SHALL add a line naming that plan.

#### Scenario: Nested repo
- **WHEN** a meta-repo session runs `cd nested && git commit -m x` and `nested` has an untracked file
- **THEN** the nudge lists the nested repo's file, not the meta-repo's

### Requirement: Branch created from a non-main base
`warn-branch-base` SHALL nudge (exit 0, never block) on `git checkout -b`/`-B` or `git switch -c`/`-C`/`--create` when the explicit base, or else the current branch, is not `main` or `master`. It MUST stay silent when the directory a leading `cd` names does not exist or the branch cannot be read.

#### Scenario: Stacked branch in a worktree
- **WHEN** `git checkout -b feat/y` runs in a linked worktree on `feat/x`
- **THEN** the hook exits 0 with a nudge that the branch is created from `feat/x`, not main

#### Scenario: Branch from main
- **WHEN** `git switch -c feat/y main` runs in a linked worktree
- **THEN** the hook exits 0 with no message

### Requirement: Branching in a primary checkout
In a primary checkout where `enforce-worktree` would block, `warn-branch-base` SHALL nudge that branching in a primary checkout is the pattern `enforce-worktree` prevents and point to creating a worktree, whatever base is named.

#### Scenario: Branch in the primary
- **WHEN** `git checkout -b feat/y main` runs in the primary checkout of a branch-mode repo
- **THEN** the hook exits 0 with the worktree-first nudge
