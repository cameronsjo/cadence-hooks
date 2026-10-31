# worktree-enforcement Specification

## Purpose
Worktree discipline for branch-mode repositories (any git repository that has not declared itself main-by-design with `CADENCE_ALLOW_MAIN`): `cadence-hooks guardrails enforce-worktree` blocks a commit into, or a file edit in, a shared primary checkout, with the snooze `cadence-hooks guardrails dismiss-enforce-worktree`; `cadence-hooks guardrails warn-main-branch` and its snooze `cadence-hooks guardrails dismiss-main-branch-warn`, `cadence-hooks guardrails warn-subagent-worktree` and `cadence-hooks guardrails warn-entry-posture` are advisory nudges that never block.

## Requirements

### Requirement: Primary-checkout commits and edits block
`enforce-worktree` SHALL block (exit 2) a PreToolUse Bash command whose `git commit` lands in the primary checkout of a branch-mode repository, and an `Edit`, `Write` or `MultiEdit` of a file in the primary checkout of the session's own repository. A commit or edit in a linked worktree MUST be allowed.

#### Scenario: Commit in the primary
- **WHEN** the session cwd is the primary checkout of a repo on `main` and a Bash command runs `git commit -m x`
- **THEN** the hook exits 2 and stderr says the repo is a primary checkout

#### Scenario: Ordinary work in a worktree
- **WHEN** the session cwd is a linked worktree and a Bash command runs `git add -A && git commit -m x`
- **THEN** the hook exits 0 with no message

#### Scenario: Read-only command in the primary
- **WHEN** the session cwd is the primary checkout and a Bash command runs `git status && cargo test`
- **THEN** the hook exits 0 with no message

### Requirement: Block message names every way out
The block message SHALL begin `Blocked:` followed by the backtick-quoted repo path and `is a primary checkout`, and MUST name how to create a worktree, the `dismiss-enforce-worktree` command (with `--repo <path>` when the judged repo is not the one the shell starts in), `CADENCE_ALLOW_MAIN` and `CADENCE_NO_ENFORCE_WORKTREE`.

#### Scenario: Cross-repo block
- **WHEN** a commit from repo A is blocked against repo B's primary
- **THEN** the suggested dismiss command carries `--repo` naming B

### Requirement: Commit targets are read from the command
The commit arm SHALL judge every commit target the command names: a plain `cd <dir> &&` before the commit, `git -C <path>` (repeated hops accumulate), `--work-tree`, `--git-dir`, `GIT_WORK_TREE=` and `GIT_DIR=` prefixes and exported values, and commits inside `sh -c`, `$(...)`, backticks or a heredoc a shell runs. A commit into a foreign primary MUST block; a commit into a worktree from the primary MUST be allowed.

#### Scenario: Commit into a sibling primary
- **WHEN** the session works in repo A's worktree and runs `git -C /src/B commit -m x`, where `/src/B` is B's primary checkout
- **THEN** the hook exits 2 naming `/src/B`

#### Scenario: Work tree that names no repo
- **WHEN** a command runs `git --work-tree=/nonexistent/x commit -m x` from a linked worktree
- **THEN** the hook exits 0

### Requirement: Unreadable commit targets warn instead of block
Per ADR-0046, when `enforce-worktree` cannot read where a commit lands, it SHALL let the command run with a warning (exit 0, beginning `enforce-worktree cannot tell where this commit lands`) naming what it could not read. This covers an unreadable `git -C`, `--git-dir` or inline `GIT_DIR=` value, a commit hidden in a brace expansion past its bounds, and a `cd` it could not follow in a non-plain command.

#### Scenario: Variable -C from the primary
- **WHEN** the session cwd is a primary checkout and a command runs `git -C "$tmp" commit -m x`
- **THEN** the hook exits 0 with a warning naming `-C $tmp`

### Requirement: Readable targets still block beside an unreadable one
A commit target the guard does read MUST still block from a primary even when the command also holds an unreadable value: another commit into a primary in the same command, an absolute readable `-C` after the unreadable one, an unreadable `--work-tree` with no git dir (git still finds the repository from the cwd), an exported `GIT_DIR="$V"`, a commit in a `trap` action, and a commit behind unreadable runner options.

#### Scenario: Unreadable -C beside a readable primary commit
- **WHEN** from a linked worktree a command runs `git -C "$tmp" commit -m x; git -C /src/A commit -m y`, where `/src/A` is a primary checkout
- **THEN** the hook exits 2

#### Scenario: Unreadable work tree alone
- **WHEN** the session cwd is a primary checkout and a command runs `git --work-tree="$W" commit -m x`
- **THEN** the hook exits 2

#### Scenario: Exported git dir
- **WHEN** the session cwd is a primary checkout and a command runs `export GIT_DIR="$V"; git commit -m x`
- **THEN** the hook exits 2

### Requirement: Main-by-design and kill-switch exemptions
`enforce-worktree` SHALL allow when `CADENCE_ALLOW_MAIN` is truthy (`1`, `true`, `yes`) in the process environment, which exempts every repo the session touches, or in the target repo's own `.claude/settings.local.json` or `.claude/settings.json` `env` block, or when `CADENCE_NO_ENFORCE_WORKTREE` is truthy. The first such allow on a would-block target per session, repo and agent SHALL be recorded as a `used` row in `bypasses.jsonl`.

#### Scenario: Main-by-design repo
- **WHEN** the target repo's `.claude/settings.json` has `"env": {"CADENCE_ALLOW_MAIN": "true"}` and a commit lands in its primary
- **THEN** the hook exits 0 and a bypass `used` row is recorded

### Requirement: Path and repo carve-outs
`enforce-worktree` SHALL allow when the repo root is under a temp directory (`/tmp`, `/private/tmp`, `$TMPDIR`); the edited file is inside a `.claude/` directory, under `docs/plans/`, or untracked and gitignored; the repository has no commit on any ref; or the edited file is in a different repository than the session's.

#### Scenario: Plan doc on main
- **WHEN** an Edit writes `docs/plans/2026-10-20-x.md` in the primary checkout
- **THEN** the hook exits 0

#### Scenario: Foreign artifact drop
- **WHEN** a session in repo A writes a note into a vault repo's primary checkout
- **THEN** the hook exits 0

#### Scenario: Bootstrap commit
- **WHEN** a fresh `git init` repo with no commits runs `git commit -m init` in its primary
- **THEN** the hook exits 0

### Requirement: Subprocess mutations in the primary nudge
When no commit blocks and none rode a bypass, `enforce-worktree` SHALL nudge (exit 0, never block) when a Bash command in the session's own primary checkout runs a package-manager manifest mutator (such as `uv add`, `cargo add`, `npm install`), `sed -i` or `tee` on an existing file, or a `>`/`>>` redirect into an existing file. A redirect to a file outside the repository, or to a path built from a variable, MUST draw no nudge.

#### Scenario: In-place edit
- **WHEN** the session cwd is a primary checkout and a command runs `sed -i 's/a/b/' src/lib.rs`
- **THEN** the hook exits 0 with a nudge naming the path

#### Scenario: Scratch redirect
- **WHEN** a command runs `git diff > /tmp/report.txt` from the primary
- **THEN** the hook exits 0 with no message

### Requirement: Fail-open and scope
`enforce-worktree` SHALL allow when the target is not in a git repository, git is unavailable, or a git probe hits the hook deadline. It SHALL exit 0 with no output in a Claude Code cloud session (`CLAUDE_CODE_REMOTE=true`). It is not a protected guard, so `CADENCE_DISABLE=enforce-worktree` SHALL switch it off.

#### Scenario: Not a repository
- **WHEN** an Edit targets a file in a directory that is not a git repository
- **THEN** the hook exits 0

#### Scenario: Cloud session
- **WHEN** `CLAUDE_CODE_REMOTE=true` and a commit lands in the clone's primary checkout
- **THEN** the hook exits 0 with no output

### Requirement: Snoozing enforce-worktree
`cadence-hooks guardrails dismiss-enforce-worktree [--for DURATION] [--reason TEXT] [--repo PATH]` SHALL write an expiry marker at `<git common dir>/cadence-hooks/enforce-worktree-snoozed-until`, shared by every worktree of the repo, plus a provenance sidecar, record an `armed` row in `bypasses.jsonl`, print `enforce-worktree unblocked for <duration> in <repo>`, and exit 0. While it is active, or when armed earlier in the same `&&` chain, the guard MUST allow.

#### Scenario: Default snooze
- **WHEN** `cadence-hooks guardrails dismiss-enforce-worktree` runs in a repo
- **THEN** commits in that repo's primary are allowed for 30 minutes and the exit status is 0

### Requirement: Snooze argument rules
Both `dismiss-enforce-worktree` and `dismiss-main-branch-warn` SHALL default `--for` to `30m` and accept `<number><s|m|h|d>`. Each MUST exit 1 with a stderr message, writing no marker, for an invalid duration, a duration over 24h, a duration over 1h without `--reason`, or a directory outside any git repository. The two snoozes MUST be independent.

#### Scenario: Long snooze without a reason
- **WHEN** `cadence-hooks guardrails dismiss-enforce-worktree --for 4h` runs with no `--reason`
- **THEN** it exits 1 and writes no marker

### Requirement: Main-branch nudge
`warn-main-branch` SHALL nudge (exit 0, never block) once per session per repo on a file edit while the repo's branch is `main` or `master`, with a message beginning `You're editing files directly on '<branch>'.` that names the dismiss command and `CADENCE_ALLOW_MAIN`. It MUST stay silent for edits inside a `.claude/` directory or under `docs/plans/`, on other branches, outside a repository, when `CADENCE_ALLOW_MAIN` is truthy, and while snoozed.

#### Scenario: First edit on main
- **WHEN** a session's first Edit lands in a repo on `main`
- **THEN** the hook exits 0 with the main-branch nudge

#### Scenario: Second edit in the same session
- **WHEN** the same session edits another file in that repo
- **THEN** the hook exits 0 with no message

### Requirement: Snoozing the main-branch nudge
`cadence-hooks guardrails dismiss-main-branch-warn [--for DURATION] [--reason TEXT]` SHALL silence `warn-main-branch` for the current session in the current repo only, writing a session-keyed marker in the private per-user marker directory and an `armed` row in `bypasses.jsonl`. The 24h cap MUST also apply when the marker is read. It MUST exit 1 when no Claude Code session id is available. A peer session in the same checkout MUST still be nudged.

#### Scenario: Peer session not silenced
- **WHEN** session S1 runs `dismiss-main-branch-warn --for 2h --reason "wrap-up"` and session S2 edits on `main` in the same checkout
- **THEN** S2 receives the main-branch nudge

### Requirement: Subagent dispatch from the primary
`warn-subagent-worktree` SHALL nudge (exit 0) once per session per repo on an `Agent` or `Task` spawn when the session sits in a primary checkout, a sibling linked worktree exists, and the spawn does not set `isolation: "worktree"`. Spawns of the read-only `Explore` and `Plan` subagent types, a truthy `CADENCE_ALLOW_SUBAGENT_FROM_MAIN`, and cloud sessions MUST draw no nudge. It MUST NOT block.

#### Scenario: Dispatch beside a worktree
- **WHEN** a session in the primary checkout spawns a `general-purpose` agent while a sibling worktree exists
- **THEN** the hook exits 0 with a nudge that the subagent will work in the main checkout

#### Scenario: Isolated dispatch
- **WHEN** the spawn sets `isolation: "worktree"`
- **THEN** the hook exits 0 with no message

### Requirement: Worktree entry posture
`warn-entry-posture` SHALL check once per session per worktree, on the first `Write` or `Edit` in a linked worktree on a branch other than `main`, `master` or the default branch: with no upstream it SHALL nudge to `git push -u origin <branch>`; with an upstream but no open PR for the branch it SHALL nudge to open a draft PR. A git or gh failure or timeout, unparseable output, or an unwritable marker MUST yield silence, and it MUST NOT block.

#### Scenario: Unpushed worktree branch
- **WHEN** a session's first Edit lands in a linked worktree on `feat/x` with no upstream
- **THEN** the hook exits 0 with a nudge naming `git push -u origin feat/x`

#### Scenario: Pushed with an open PR
- **WHEN** the branch has an upstream and an open PR
- **THEN** the hook exits 0 with no message
