# session-coordination Specification

## Purpose
Session coordination gives concurrent Claude Code sessions in one checkout an identity, a liveness signal, and advisory warnings when they step on each other or leave work behind. It covers `cadence-hooks session start`, `session heartbeat`, `session guard`, `session end`, `session warn-branch-drift`, `session warn-branch-intent`, `session warn-commit-provenance`, `session backstop-record`, `session backstop-warn`, `session nudge-afk-gap`, and the CLI actions `session declare`, `session status`, and `session timer start|lap|stop`.

## Requirements

### Requirement: Registration at session start
On SessionStart, `session start` SHALL write this session's record to `<repo>/.claude/sessions/<session-id>.json`, mirror it into `<config_dir>/cadence/live-sessions/`, and ensure `.git/info/exclude` lists `.claude/sessions/`. A resume (same session id) MUST keep the declared intent and touched paths. A missing or filename-unsafe session id MUST NOT be registered, and a failed write MUST NOT stop the session.

#### Scenario: First start in a repo
- **WHEN** a session starts in a git repository with a safe session id
- **THEN** `<repo>/.claude/sessions/<session-id>.json` exists and `.git/info/exclude` contains `.claude/sessions/`

#### Scenario: Resume keeps the declared lane
- **WHEN** a session that ran `session declare --intent X --touching src/` starts again with the same session id
- **THEN** its record still carries intent `X` and the `src/` lane

### Requirement: Live-peer disclosure
`session start` SHALL sweep stale records and, when other live sessions are registered in the same checkout, nudge with one line giving their count and pointing at `cadence-hooks session status`. With no live peers and nothing else to disclose, it MUST allow silently.

#### Scenario: One live peer
- **WHEN** a session starts while one other session's record in the checkout is fresh
- **THEN** the additionalContext contains `1 other session is live in this checkout` and names `cadence-hooks session status`

#### Scenario: Empty room
- **WHEN** a session starts in a linked worktree with no peers, no in-flight plans, `cadence-rules.md` installed, and a checkout that is not behind
- **THEN** the hook exits 0 with no output

### Requirement: Start-time repo and machine disclosures
`session start` SHALL add independent lines to its nudge, each only when its condition holds: a worktree-posture line when `enforce-worktree` would block an edit here; a `Checkout: N commits behind origin/<default>` line from cached remote-tracking refs, never a fetch; a once-per-day line when `cadence-rules.md` is not installed; and the guard fail-open disclosure. The posture and behind lines MUST appear even when registration fails.

#### Scenario: Primary checkout of a branch-mode repo
- **WHEN** a session starts in the primary checkout of a repo where `enforce-worktree` would block edits
- **THEN** the nudge contains `start feature work in a worktree` even if no peers are live

#### Scenario: Local default branch behind its cached remote ref
- **WHEN** local `main` is one commit behind `refs/remotes/origin/main`
- **THEN** the nudge contains `1 commits behind origin/main` and no fetch is run

### Requirement: Liveness by file age
A session SHALL count as live while its registry file is younger than `CADENCE_SESSION_STALE_MINUTES` (default 30). The refresh MUST ride the every-PostToolUse `session persist-plan-approval` process, at most once per third of the window, and each refresh MUST sweep stale peers. The machine-wide mirror MUST be swept on the default window whatever a session's override.

#### Scenario: Quiet peer goes stale
- **WHEN** a peer's registry file has not been touched for more than 30 minutes and no override is set
- **THEN** the peer is no longer disclosed and the next refresh or start removes its file

#### Scenario: Throttled refresh
- **WHEN** a session makes many tool calls within one minute under the default window
- **THEN** its registry file is rewritten at most once in that minute

### Requirement: Heartbeat subcommand
`session heartbeat` SHALL refresh this session's record and sweep stale peers, and MUST never block or error. It SHALL update the observed branch on every run but move the drift baseline only when the triggering command is this session's own `git checkout` or `git switch` in its own working tree.

#### Scenario: Peer moves shared HEAD
- **WHEN** `session heartbeat` runs after a tool call that was not this session's branch switch, and HEAD now names another branch
- **THEN** the record's observed branch updates and its drift baseline stays unchanged

#### Scenario: Own switch re-baselines
- **WHEN** `session heartbeat` runs after this session's `git switch feat/y`
- **THEN** the drift baseline becomes `feat/y`

### Requirement: Deregistration at session end
`session end` SHALL remove this session's record from the mirror and from the repo registry, and MUST act only when `hook_event_name` is `SessionEnd`. The mirror record MUST be removed even when the cwd is outside any git repository. It never blocks.

#### Scenario: Session exits
- **WHEN** `session end` receives a SessionEnd payload for a registered session
- **THEN** its file is gone from `.claude/sessions/` and from `<config_dir>/cadence/live-sessions/`

#### Scenario: Misrouted event
- **WHEN** `session end` receives a PostToolUse payload
- **THEN** no registry file is removed

### Requirement: Peer lane guard
On PreToolUse with live peers, `session guard` SHALL nudge, and MUST NOT block, on a branch switch, blanket staging (`git add -A`, `git commit -a`), or a write into a peer's `--touching` path by `Edit`, `MultiEdit`, `Write`, or a Bash command whose target it can resolve. Each nudge MUST append a row to `guard_nudges.jsonl`. No live peers, or a missing cwd or session id, MUST allow.

#### Scenario: Branch switch with a live peer
- **WHEN** a peer is live and the session runs `git checkout feature/x`
- **THEN** the hook exits 0 with a `Heads up:` nudge that the switch yanks the working tree out from under the peer

#### Scenario: Ordinary command is allowed
- **WHEN** a peer is live and the session runs `git status`
- **THEN** the hook exits 0 with no output

#### Scenario: Edit inside a declared lane
- **WHEN** a peer declared `src/auth/` and the session edits `src/auth/login.rs`
- **THEN** the hook nudges that the path is inside the peer's declared lane and to check with the user

### Requirement: Commit-time branch drift warning
On a Bash `git commit`, `session warn-branch-drift` SHALL nudge when the live branch differs from this session's drift baseline, naming both and asking to re-verify with `git branch --show-current` and `git status`. It MUST NOT block. No baseline, a detached HEAD, a non-repo cwd, or no session id MUST allow.

#### Scenario: HEAD moved by someone else
- **WHEN** the baseline is `feat/a` and HEAD is on `feat/b` at `git commit`
- **THEN** the hook exits 0 with a nudge naming `feat/b` as HEAD and `feat/a` as the recorded branch

#### Scenario: Ordinary commit is allowed
- **WHEN** the baseline and HEAD are both `feat/a` at `git commit`
- **THEN** the hook exits 0 with no output

### Requirement: Stale-branch intent nudge
On `Edit`, `Write`, or `NotebookEdit`, `session warn-branch-intent` SHALL nudge once per session when all gates hold: the branch is not `main` or `master`, the session declared an intent, the branch has commits not on the default branch, its tip predates the session, and intent and branch share no substantive token. Any missing piece MUST allow. `CADENCE_ALLOW_BRANCH_INTENT` set to `1`, `true`, or `yes` MUST silence it.

#### Scenario: New work on an old unrelated branch
- **WHEN** the intent is `fix login timeout`, the branch `feat/billing-export` has its own commits older than the session, and the session edits a file
- **THEN** the hook nudges once, suggests branching fresh off main, and names `CADENCE_ALLOW_BRANCH_INTENT`

#### Scenario: Related branch name
- **WHEN** the intent mentions `cadence-hooks#54` and the branch is `feat/54-registry`
- **THEN** the hook exits 0 with no output

#### Scenario: Intent declared later
- **WHEN** the session edits before declaring any intent, then declares one
- **THEN** the first edit is allowed silently and a later edit still gets its one evaluation

### Requirement: Commit provenance trailer nudge
On a Bash `git commit` whose message it can read and that lacks `Session-Id:`, `session warn-commit-provenance` SHALL nudge once per session with a ready-to-copy `Session-Id:`, `Model:`, `Harness:`, and `Machine:` block, omitting unresolvable lines. `Machine:` MUST be a salted hostname digest, or `cloud` under `CLAUDE_CODE_REMOTE`. An unreadable message, or one with the trailer, MUST draw no provenance nudge. It MUST NOT block.

#### Scenario: Commit without a trailer
- **WHEN** a session runs `git commit -m "fix: x"` for the first time
- **THEN** the hook nudges with a block containing `Session-Id: <this session's id>` and a `Machine:` line that is not the raw hostname

#### Scenario: Second commit in the same session
- **WHEN** the nudge already fired this session and another trailer-less commit runs
- **THEN** the hook exits 0 with no output

#### Scenario: Message from a file
- **WHEN** a session runs `git commit -F msg.txt` and `msg.txt` contains `Session-Id: abc`
- **THEN** the hook exits 0 with no output

### Requirement: Loose-ends backstop
On SessionEnd, `session backstop-record` SHALL write uncommitted, unpushed, stash, and other-worktree unpushed counts to `.claude/sessions/.loose-ends`, only when no other session is live in any worktree of the repo and a count is non-zero. On the next SessionStart, `session backstop-warn` SHALL nudge once with them and delete the marker, never claiming `/outro` was skipped. A non-empty `CADENCE_NO_OUTRO_BACKSTOP` MUST disable both.

#### Scenario: Last session leaves a dirty tree
- **WHEN** the only live session ends with 2 uncommitted files and the next session starts
- **THEN** the next start nudges `Last session in this repo ended with loose ends: 2 uncommitted` and a second start is silent

#### Scenario: A peer is still working
- **WHEN** a session ends while a peer is live in a sibling worktree of the same repo
- **THEN** no marker is written

### Requirement: Opt-in idle-gap marker
`session nudge-afk-gap` SHALL do nothing, reading and writing no file, unless `CADENCE_AFK_GAP` is `1`, `true`, or `yes`. Enabled, it SHALL stamp each prompt under `<metrics_dir>/state/` and inject one line such as `6 hours later…` when the gap since the later of the last prompt and the tool-activity stamp reaches `CADENCE_AFK_GAP_MINUTES` (default 240). A session's first prompt MUST be silent.

#### Scenario: Return after six hours
- **WHEN** `CADENCE_AFK_GAP=1` and the session's last activity was six hours before this prompt
- **THEN** the additionalContext starts with `6 hours later…` and asks to re-check git state, peers, and earlier claims

#### Scenario: Disabled by default
- **WHEN** `CADENCE_AFK_GAP` is unset
- **THEN** the hook exits 0 with no output and writes no stamp

#### Scenario: Unparsable threshold
- **WHEN** `CADENCE_AFK_GAP_MINUTES=0` and the gap is three hours
- **THEN** the 240-minute default applies and the hook is silent

### Requirement: Declare CLI action
`session declare [--intent TEXT] [--touching PATH]... [--session-id ID]` SHALL upsert this session's record in the repo registry and the mirror. The id MUST resolve from `--session-id`, then `CLAUDE_SESSION_ID`, then `CLAUDE_CODE_SESSION_ID`, skipping unsafe candidates. An omitted field MUST be kept and a blank one cleared. It SHALL always exit 0, reporting problems on stdout.

#### Scenario: Declare from the Bash tool
- **WHEN** `cadence-hooks session declare --intent "cadence-hooks#54"` runs with only `CLAUDE_CODE_SESSION_ID` set
- **THEN** that session's record carries the intent and the command exits 0

#### Scenario: Blank intent clears
- **WHEN** `session declare --intent " "` runs for a session whose intent was `X`
- **THEN** the record no longer carries an intent and its touched paths are unchanged

### Requirement: Status CLI action
`session status` SHALL list live and stale sessions across the current checkout and every worktree `git worktree list` names, marking stale ones `[STALE]`. It MUST exit 0 for any answer, including an empty registry, and exit 1 with a stderr message outside a git repository. It and `session declare` MUST keep working under `CADENCE_BYPASS=1`.

#### Scenario: Empty registry
- **WHEN** `cadence-hooks session status` runs in a repo with no registered sessions
- **THEN** it prints `No sessions registered in` the registry path and exits 0

#### Scenario: Status outside a repository
- **WHEN** `cadence-hooks session status` runs in a directory that is not a git repository
- **THEN** it exits 1 with `session status: not inside a git repository.` on stderr

### Requirement: Wall-clock timer CLI action
`session timer start|lap|stop [LABEL] [--session-id ID]` SHALL keep named timers (default `default`) scoped to the resolved session, else a shared scope. `start` records now; `lap` prints elapsed time; `stop` prints it, removes the timer, and appends `{ts, sessionId, label, elapsedMs}` to `<metrics_dir>/timers.jsonl`. An invalid label, a timer never started, or an unwritable state MUST exit 1 with the reason on stderr.

#### Scenario: Stop a running timer
- **WHEN** `session timer start build` then `session timer stop build` run
- **THEN** stop prints the elapsed time, exits 0, and `timers.jsonl` gains one row with label `build`

#### Scenario: Stop without start
- **WHEN** `session timer stop never-started` runs
- **THEN** it exits 1 with the reason on stderr

#### Scenario: Label with a slash
- **WHEN** `session timer start a/b` runs
- **THEN** it exits 1 because only letters, digits, `-`, `_`, and `.` are allowed

### Requirement: Advisory and fail-open behavior
Every session-coordination hook MUST exit 0: an unreadable registry, a failed git call, or a missing payload field SHALL degrade to a silent allow. Text from registry files, markers, or git refs MUST have control characters flattened and length capped before it reaches additionalContext. The nudges of `warn-branch-drift`, `warn-branch-intent`, `warn-commit-provenance`, and `backstop-warn` MAY be silenced by the repo's `.claude/cadence.json` `nudges` map.

#### Scenario: Crafted marker text
- **WHEN** a `.loose-ends` marker with unpushed commits names a branch containing a newline followed by instruction text
- **THEN** the `session backstop-warn` nudge renders that branch on one line, truncated to the display cap

#### Scenario: Repo silences a suppressible nudge
- **WHEN** `.claude/cadence.json` has `"nudges": {"backstop-warn": {"suppress": true}}` and a loose-ends marker exists
- **THEN** `session backstop-warn` emits no additionalContext

### Requirement: Cloud session behavior
Under `CLAUDE_CODE_REMOTE=true`, `start`, `heartbeat`, `guard`, `end`, `backstop-record`, `backstop-warn`, and `nudge-afk-gap` SHALL exit 0 with no output before doing any work, because the registry and activity stamps are machine-local. `warn-branch-drift`, `warn-branch-intent`, and `warn-commit-provenance` MUST run as they do locally.

#### Scenario: Cloud session start
- **WHEN** `session start` runs with `CLAUDE_CODE_REMOTE=true`
- **THEN** it exits 0 with no output and writes no registry file

#### Scenario: Cloud commit
- **WHEN** `session warn-commit-provenance` fires with `CLAUDE_CODE_REMOTE=true`
- **THEN** its block carries `Machine: cloud`

### Requirement: Conflicted-merge commit keeps its conflicts block below the trailers
`session warn-commit-provenance` SHALL nudge on a `git commit --no-edit` that would finish a conflicted merge whose pending message (MERGE_MSG) has a trailer line above git's `# Conflicts:` block, and the nudge SHALL advise amending the landed commit before it is pushed, and only where that commit's message still shows the block. It MUST read only that plain shape and otherwise stay silent, MUST NOT echo the message, MUST NOT block, and MUST NOT use up the once-per-session provenance nudge.

#### Scenario: Finishing a conflicted merge with trailers
- **WHEN** a merge started with a message ending in `Session-Id:` and `Co-Authored-By:` lines stopped on a conflict, and a session runs `git commit --no-edit`
- **THEN** the hook exits 0 with a nudge that says the commit lands with the block below the trailers and names `git commit --amend --no-edit --cleanup=strip`

#### Scenario: The nudge says what strip drops
- **WHEN** the hook nudges for that merge
- **THEN** the nudge says `--cleanup=strip` drops every line that starts with `#`, and names `git commit --amend -F` on a copy of `git log -1 --format=%B` cut at the `# Conflicts:` line for a message that has other such lines

#### Scenario: The nudge advises an amend, not a second commit
- **WHEN** the hook nudges for that merge, which is context with no permission decision, so the commit has landed and MERGE_MSG is gone when the nudge is read
- **THEN** the nudge names no copy of MERGE_MSG and no `git commit --no-edit --cleanup=strip`

#### Scenario: The amend is conditional on HEAD still being the merge
- **WHEN** the hook nudges for that merge, and a later command in the same call may have moved HEAD (a commit, a branch switch, a merge abort), or the commit ran in another worktree
- **THEN** the nudge says to run the amend in the directory the commit ran in, and only if `git log -1 --format=%B` there still shows the `# Conflicts:` block, and otherwise to leave HEAD alone

#### Scenario: The cleanup is already asked for
- **WHEN** the same session runs `git commit --no-edit --cleanup=strip`
- **THEN** the hook adds no conflicts nudge

#### Scenario: An editor opens
- **WHEN** the same session runs `git commit --no-edit --edit`
- **THEN** the hook adds no conflicts nudge

#### Scenario: The command names its own message
- **WHEN** the same session runs `git commit --no-edit -m "Merge feat"`, or `git -C <dir> commit --no-edit`
- **THEN** the hook adds no conflicts nudge

#### Scenario: No trailers above the block
- **WHEN** the merge was started with `-m "fix: resolve the merge"` and a session runs `git commit --no-edit`
- **THEN** the hook adds no conflicts nudge
