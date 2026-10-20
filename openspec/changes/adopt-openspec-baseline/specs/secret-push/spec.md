## Purpose
Secret push stops a `git push` from publishing a secret: `cadence-hooks cadence prevent-secret-push` reads what the push would send, before it runs, and blocks when a commit adds a secret-named file or a credential token, or when a commit message, tag object, or pushed ref name carries one.

## ADDED Requirements

### Requirement: Every push the command runs is judged
On PreToolUse for Bash, `prevent-secret-push` SHALL find every `git push` the command would run, including behind command runners, `git -C <dir>`, `cd` to a literal directory, chains, substitutions, and `sh -c` scripts, and judge each one in the directory it runs in. A command that runs no push, and a push whose outbound range holds nothing new, MUST be allowed silently.

#### Scenario: Ordinary push is allowed
- **WHEN** a Bash command runs `git push origin main` and the outbound commits carry no secret
- **THEN** the hook allows silently

#### Scenario: Non-push commands
- **WHEN** a Bash command runs `git status` or `echo git push`
- **THEN** the hook allows

#### Scenario: Push in another directory
- **WHEN** a Bash command runs `git -C /repo push origin main` from an unrelated directory and `/repo` has an outbound commit carrying a token
- **THEN** the hook blocks

### Requirement: The outbound range is what no remote has
For each named source the guard SHALL scan the commits reachable from it and not reachable from any remote-tracking ref, so a commit already on any remote reads as published and a first push to an empty remote scans the whole history. `tag <name>` SHALL mean `refs/tags/<name>` and `@` SHALL mean `HEAD`.

#### Scenario: Already published secret
- **WHEN** a commit carrying a token was pushed earlier and a new clean commit is pushed now
- **THEN** the hook allows

#### Scenario: Pushing another branch
- **WHEN** branch `branchB` carries a token, `main` does not, and the command is `git push origin branchB`
- **THEN** the hook blocks, while `git push origin main` allows

#### Scenario: First push
- **WHEN** no remote-tracking refs exist and an old commit in history carries a token
- **THEN** the hook blocks

### Requirement: Widening flags widen the range
`--all` and `--branches` SHALL widen the range to every local branch and `--mirror` (flag or `remote.<name>.mirror`) to every ref. `--tags`, `--follow-tags`, and `push.followTags` MUST add the tag objects they would publish, re-reading tags the remote may already have.

#### Scenario: Tags push
- **WHEN** an annotated tag's message carries a token and the command is `git push --tags`
- **THEN** the hook blocks

#### Scenario: All branches
- **WHEN** a branch other than the current one carries a token and the command is `git push --all`
- **THEN** the hook blocks

### Requirement: Credential tokens in outbound content block
The guard SHALL scan every outbound commit's added lines, including the root commit and what a merge introduces, so a secret added then removed inside the range is still caught. Content MUST be matched by token grammar (known prefix, charset, length), never a list of values. The message SHALL list findings as short sha, path, and kind, at most five then `...and more`, MUST NOT contain the value, and SHALL say to rotate the secret and rewrite the commit.

#### Scenario: AWS key in a committed file
- **WHEN** an outbound commit adds `key=AKIA…` to `src/cfg.txt`
- **THEN** the hook exits 2 and stderr contains `src/cfg.txt` and `AWS access key id` but not the key

#### Scenario: Token kinds
- **WHEN** outbound content holds a GitHub, GitLab, npm, Slack, Stripe live, Google API, or `sk-` key, or a PEM private-key header
- **THEN** the hook blocks naming the kind

#### Scenario: Added then removed
- **WHEN** one outbound commit adds a token and a later outbound commit deletes it
- **THEN** the hook blocks

### Requirement: The scan reads what the push sends
Every git process the guard runs SHALL read the objects the push would send: replace refs MUST be off, and config that can hide content (root-commit display, relative diffs, external diff drivers, textconv, renames, binary attributes, path quoting) MUST be neutralized.

#### Scenario: Binary attribute
- **WHEN** `.gitattributes` marks a file binary and an outbound commit adds a token to it
- **THEN** the hook blocks

#### Scenario: Replace ref
- **WHEN** a replace ref maps an outbound commit carrying a token to a clean one
- **THEN** the hook blocks

### Requirement: Secret-named files block by name
An outbound commit that adds or modifies a file whose name is in the shared secret deny set SHALL block as a `secret-named file` even when its content matches no pattern. A name with a safe-template suffix (`.example`, `.template`, `.sample`, `.defaults`, `.test`, `.ci`, `.pub`) MUST skip the name check and still have its content scanned. Deleting a secret-named file SHALL be allowed.

#### Scenario: Committed dotenv file
- **WHEN** an outbound commit adds `.env` containing `FOO=bar`
- **THEN** the hook blocks naming `.env` and `secret-named file`

#### Scenario: Template with a real key
- **WHEN** an outbound commit adds `.env.example` containing a GitHub token
- **THEN** the hook blocks on the content

#### Scenario: Deleting a secret file
- **WHEN** the only outbound commit removes `.env`
- **THEN** the hook allows

### Requirement: Messages, tags, and ref names are scanned
The guard SHALL scan each outbound commit's raw header and message, each annotated tag object the push would publish, and every ref name the push writes (both sides of each refspec, the current branch of a bare push, every ref a widening flag enumerates). A finding in a ref name MUST block without echoing the ref name.

#### Scenario: Token in a commit message
- **WHEN** an outbound commit's message contains a GitHub token
- **THEN** the hook blocks

#### Scenario: Token in a branch name
- **WHEN** the pushed refspec's destination name contains a token
- **THEN** the hook blocks and stderr does not contain that name

### Requirement: Dry runs and deletions are allowed
A push with `--dry-run` or `-n`, and a push that only deletes remote refs, MUST be allowed, because nothing is published. A push that deletes one ref and publishes another SHALL still scan what it publishes.

#### Scenario: Dry run
- **WHEN** an outbound commit carries a token and the command is `git push --dry-run origin main`
- **THEN** the hook allows

#### Scenario: Delete plus publish
- **WHEN** the command deletes one remote branch and pushes a branch carrying a token
- **THEN** the hook blocks

### Requirement: A detected push it cannot fully scan blocks
Once a push is detected, the guard SHALL block rather than allow when it cannot scan the push completely, and only a genuinely empty range SHALL allow. The message MUST begin `BLOCKED: git push refused`, say why, and say the guard fails closed.

#### Scenario: Limits
- **WHEN** a push would publish more than 2000 new commits, a patch over 32 MiB, or more than 16 refspec sources
- **THEN** the hook blocks, for the commit cap with `the range is too large to fully scan` even when the newest 2000 are clean

#### Scenario: Unresolvable or non-commit sources
- **WHEN** a push names a source it cannot resolve, a tag or ref pointing at a tree or blob, a nested tag, or a full-length hex source that a ref is also named like
- **THEN** the hook blocks

#### Scenario: Broken git
- **WHEN** a git process the guard runs fails, is missing, or times out
- **THEN** the hook blocks

#### Scenario: Unscannable encoding
- **WHEN** an outbound commit's `encoding` header is not UTF-8, US-ASCII, or ISO-8859
- **THEN** the hook blocks

### Requirement: Pushes outside the model block
The guard SHALL block `git send-pack`, `git http-push`, `git remote-<transport>` (never the builtin `git remote`), a dashed `git-push`, and `exec -a` naming a git argv[0]. It SHALL block a submodule-recursing push only in a repository that has submodules. A git command that sets on its own line a value git runs as a command MUST block, except an empty value, a pager of `cat`, or an empty config environment.

#### Scenario: Unscannable transport
- **WHEN** a Bash command runs `git send-pack origin main`
- **THEN** the hook blocks, while `git remote -v` allows

#### Scenario: Command-valued config
- **WHEN** a Bash command runs `GIT_SSH_COMMAND='ssh -i key' git push` or `git -c core.sshCommand=x push`
- **THEN** the hook blocks

#### Scenario: Submodule push without submodules
- **WHEN** a Bash command runs `git push --recurse-submodules=on-demand` in a repository with no `.gitmodules` and no gitlinks
- **THEN** the hook judges it as an ordinary push

### Requirement: A commit made in the same call names the split
Because the guard reads the repository before the command runs, a push whose source a same-call `git commit` or `git switch -c` has not created yet SHALL block with advice that names that command, says it `has not run`, and says to push in the next call. A push of an unborn branch with no writer in the command SHALL say it `has no commit yet`. Split into two calls, the commit MUST be scanned like any other.

#### Scenario: Commit and push together
- **WHEN** a Bash command runs `git add f; git commit -m first; git push origin HEAD:refs/heads/main2` on an orphan branch
- **THEN** the hook blocks naming `git commit` and the next call

### Requirement: Aliases that could push are not invisible
A `git <sub>` spelled exactly as a git builtin SHALL never be probed as an alias. Any other subcommand MUST be looked up in the repository's config, following alias-of-alias, and SHALL block as unresolved when the alias pushes or starts with `!`, the same command writes it, the subcommand word carries `$` or a backtick, the command names config the probe cannot see, the probe fails, or `help.autocorrect` would run a guess.

#### Scenario: Alias that pushes
- **WHEN** the repository config sets `alias.pp = push` and the command is `git pp origin main`
- **THEN** the hook blocks naming the alias

#### Scenario: Alias that does not push
- **WHEN** the config sets `alias.lg = log --oneline` and the command is `git lg -1`
- **THEN** the hook allows

#### Scenario: Builtin is not probed
- **WHEN** the command is `git status`
- **THEN** the hook allows without probing an alias

#### Scenario: Config the probe cannot see
- **WHEN** the command is `GIT_CONFIG_GLOBAL=/x git zz`
- **THEN** the hook blocks

### Requirement: The acknowledgement escape
When `CADENCE_ALLOW_SECRET_PUSH` is truthy (`1`, `true`, `yes`) in the hook's environment, a push the guard would block SHALL be allowed and a bypass row recorded. The escape MUST be read only once a block is decided, so a clean push records no row, and falsy values MUST NOT open it. An inline `CADENCE_ALLOW_SECRET_PUSH=1 git push` prefix MUST NOT count, and every block message SHALL say where to set it.

#### Scenario: Acknowledged push
- **WHEN** `CADENCE_ALLOW_SECRET_PUSH=1` is in the hook's environment and the outbound commit carries a token
- **THEN** the hook allows and records a bypass row naming `CADENCE_ALLOW_SECRET_PUSH`

#### Scenario: Falsy values
- **WHEN** the variable is `0`, `no`, or empty and the outbound commit carries a token
- **THEN** the hook blocks

#### Scenario: Escape set with nothing to block
- **WHEN** the escape is set and the push is clean
- **THEN** the hook allows and records no bypass row

### Requirement: Documented allowances
The guard SHALL exempt from the content scan every file of a repository whose top-level path has a `cadence-hooks` component, still checking names and messages, and MUST NOT exempt a `cadence-hooks/` directory inside another repository. It SHALL trust any remote-tracking ref as published and SHALL NOT scan Git LFS object content. Pushes it does not detect (`gh repo create --push`, `git subtree push`, a push inside a script file) MUST be allowed.

#### Scenario: This repository's fixtures
- **WHEN** a commit in a repository at `/src/cadence-hooks` adds a test file holding a fake AWS key
- **THEN** the hook allows the push

#### Scenario: Push inside a script
- **WHEN** a Bash command runs `bash scripts/release.sh` and the script pushes
- **THEN** the hook allows

### Requirement: Read-only, protected, and remote-armed
The guard MUST NOT change the repository or the remote while scanning, and every git process it runs SHALL be bounded by the shared hook deadline. It SHALL be a protected guard: naming it in `CADENCE_DISABLE` MUST NOT switch it off, and only `CADENCE_BYPASS=1` does. It SHALL run in remote (cloud) sessions.

#### Scenario: Remote untouched
- **WHEN** the guard blocks a push
- **THEN** the remote repository has the same commits as before

#### Scenario: Disable refused
- **WHEN** `CADENCE_DISABLE=prevent-secret-push` is set and an outbound commit carries a token
- **THEN** the hook still blocks
