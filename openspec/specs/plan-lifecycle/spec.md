# plan-lifecycle Specification

## Purpose
Plan lifecycle keeps an approved plan durable and in step with the work: it persists the plan at approval, gates the plan's shape before it is presented, surfaces in-flight plans to a resuming session, and nudges when commits, PR flips, or model switches drift from the plan. It covers `cadence-hooks session persist-plan-approval`, `session lint-plan-shape`, `session nudge-plan-tick`, `session warn-plan-ready-flip`, `session plan-driver`, `session plans`, and the plan lines of `session start`.

## Requirements

### Requirement: Persist a same-session approval
On PostToolUse for `ExitPlanMode`, `session persist-plan-approval` SHALL write the plan to `<plans_dir>/<local-date>-<slug>.md`, the slug taken from its first heading. The text SHALL come from the tool response, else the tool input, else the `planFilePath` plan-store file, with harness-appended trailing paragraphs stripped. Only a top-level approval (response says not an agent, no `agent_id`) MUST persist.

#### Scenario: Top-level approval in a repo
- **WHEN** a top-level session approves a plan headed `# Add retry budget` on 2026-10-20 in a repo whose remotes all fall under `CADENCE_ALLOWED_OWNERS`
- **THEN** `docs/plans/2026-10-20-add-retry-budget.md` is created and the hook exits 0 with a nudge beginning `Approved plan persisted to`

#### Scenario: Subagent approval
- **WHEN** the `ExitPlanMode` payload carries an `agent_id`
- **THEN** no plan file is written and the hook exits 0 with no output

### Requirement: Persist an approve-and-clear pickup
For an approve-and-clear, the hook SHALL persist from the child session's PostToolUse events when its first user message is the injected `Implement the following plan:` prompt, setting `approved_session_id` to the parent. It MUST persist only when the prompt's pointer names a parent transcript under `<config_dir>/projects` holding an `ExitPlanMode` call with this exact plan. It MUST reach a verdict at most once per session.

#### Scenario: Genuine approve-and-clear
- **WHEN** a child session's first message is the injected implement-prompt whose pointer names the parent transcript holding the matching `ExitPlanMode` call
- **THEN** the plan is persisted once, attributed to the parent session

#### Scenario: Hand-typed implement prompt
- **WHEN** a session's first message starts with `Implement the following plan:` but its pointer names no transcript holding that plan
- **THEN** nothing is persisted

### Requirement: Frontmatter merged into one block
The persisted file SHALL carry one leading frontmatter block. The hook MUST write `status: "in-flight"`, `updated`, `branch`, `session_id`, `machine` (a salted hostname digest), and, when known, `approved_session_id`, `model`, and `harness`, and MUST drop plan-authored lines for those keys or `session`, `approved_in`, `body_sha256`. A plan's `status: blocked`, and its `branch:` when none resolves, MUST be kept, as MUST all other plan keys.

#### Scenario: Plan claims to be done
- **WHEN** an approved plan's own frontmatter says `status: done` and `next: wire the CLI`
- **THEN** the persisted file has one frontmatter block with `status: "in-flight"` and `next: wire the CLI`

#### Scenario: Blocked plan stays blocked
- **WHEN** an approved plan's own frontmatter says `status: blocked`
- **THEN** the persisted file keeps `status: blocked` and carries no `in-flight` status

#### Scenario: Forged attribution
- **WHEN** an approved plan's own frontmatter carries `session_id: someone-else`
- **THEN** the persisted file's `session_id` is this session's id only

### Requirement: Idempotent writes that never overwrite
The persist MUST NOT overwrite a file. When the target name holds a different plan it SHALL try suffixes `-2` through `-9`, then the session's short id, and give up silently when all are taken. A re-fire of a body this session already persisted MUST write no copy. When the earlier copy is known only from the `plan-links.jsonl` ledger (moved, deleted, or under another date), it SHALL nudge that it was already persisted and whether that copy is still there.

#### Scenario: Same approval fires twice
- **WHEN** the same session's identical approval fires a second time and the first copy is still at its name
- **THEN** no second file is written and the nudge names that existing file

#### Scenario: Earlier copy deleted
- **WHEN** this session's persisted copy was deleted and the same approval fires again
- **THEN** no file is written and the nudge says `This session already persisted this plan` and that it is no longer there

#### Scenario: Different plan, same slug and date
- **WHEN** `2026-10-20-add-retry-budget.md` already holds a different plan
- **THEN** the new plan is written to `2026-10-20-add-retry-budget-2.md`

### Requirement: Plan destination
The repo SHALL be decided by the session root (`CLAUDE_PROJECT_DIR`, else the payload `cwd`), narrowed to a linked worktree of it when `cwd` is in one. The plans directory SHALL be the repo settings' `CADENCE_PLANS_DIR` (relative, inside the checkout) or `docs/plans`. A plan with no provable repo home (no repo, any remote outside `CADENCE_ALLOWED_OWNERS` and `CADENCE_ALLOWED_REPOS`, or an escaping directory) MUST go to `<config_dir>/cadence/plans`.

#### Scenario: Repo owned by someone else
- **WHEN** the session root has a remote outside `CADENCE_ALLOWED_OWNERS` and `CADENCE_ALLOWED_REPOS`
- **THEN** the plan is written under `<config_dir>/cadence/plans` and the nudge says it was kept out of every repo

#### Scenario: Configured plans directory
- **WHEN** an owned repo's `.claude/settings.json` `env` block sets `CADENCE_PLANS_DIR` to `notes/plans`
- **THEN** the plan is written under `notes/plans/`

### Requirement: Persist nudge content
The persist nudge SHALL name the path and approving session, and MUST NOT order a commit outright: it defers to the repo's own conventions, or says not to commit in a worktree-first primary checkout. A same-session approval MUST add a reminder to announce the driver. A plan with a `Driver:` MUST add a compare-with-running-model-and-ask directive. Missing template stanzas MUST add one `format gate: plan lacks ...` sentence of static stanza names.

#### Scenario: Plan with no panel line
- **WHEN** an approved plan has every template stanza except a settled `Panel:` line
- **THEN** the nudge contains `format gate: plan lacks a settled Panel: line`

#### Scenario: Plan names an Opus driver
- **WHEN** an approved plan's `## Orchestrator` block says `Driver: opus`
- **THEN** the nudge says the recommended driver is opus and to ask the operator on any difference from the running model

#### Scenario: Primary checkout of a worktree-first repo
- **WHEN** a plan is approved in the primary checkout of a repo where `enforce-worktree` refuses commits
- **THEN** the nudge says not to commit it here and to move it into the feature worktree

### Requirement: Persist opt-out, ledger, and fail-open
A non-empty `CADENCE_NO_PERSIST_PLAN`, in the process environment or a repo's `.claude/settings.json` or `.claude/settings.local.json` `env` block, SHALL disable the persist only, not the plan guards or start-time plan lines. Each persist SHALL append a row to `<metrics_dir>/plan-links.jsonl` with session ids, `machine`, `plan_path`, and `body_sha256`. The hook MUST NOT block; any failure SHALL allow.

#### Scenario: Repo opts out
- **WHEN** a repo's `.claude/settings.json` sets `CADENCE_NO_PERSIST_PLAN` to `1` and a plan is approved there
- **THEN** no plan file and no ledger row are written and the hook exits 0

#### Scenario: Approval with no plan text
- **WHEN** an `ExitPlanMode` PostToolUse payload carries no plan text and no readable `planFilePath`
- **THEN** the hook exits 0 with no output

### Requirement: Plan-shape gate blocks only on the Panel line
On PreToolUse for a top-level `ExitPlanMode`, `session lint-plan-shape` SHALL block (exit 2) when the plan has no settled `Panel:` line: `Panel: <seats> ran — <counts>` or `Panel: none — <reason>` with a non-trivial reason, at line start outside fences, quotes, and comments. The reason MUST name the escape `Panel: none — <reason>` and list other missing stanzas as advisory only. Every other shape MUST be allowed.

#### Scenario: Harness-template plan
- **WHEN** a top-level session calls `ExitPlanMode` with a plan of Context, Changes, and Verification sections and no `Panel:` line
- **THEN** the hook exits 2 with a reason naming `Panel: none — <reason>`

#### Scenario: Trivial escape reason
- **WHEN** the plan's only panel line is `Panel: none — n/a`
- **THEN** the hook blocks

#### Scenario: Dash variants accepted
- **WHEN** the plan carries `Panel: none -- docs-only change` and every other stanza
- **THEN** the hook does not block

### Requirement: Plan-shape gate nudges and reminders
Every judged `session lint-plan-shape` outcome SHALL carry the reminders `Make sure all your subagents have stopped.` and `Did your operator ask to see the plan?`. A plan with a settled `Panel:` line but other stanzas missing MUST draw a nudge naming them, and a fully template-shaped plan MUST draw a nudge with only the reminders. The gate MUST render only static stanza names, never plan text.

#### Scenario: Template-shaped plan is allowed
- **WHEN** the plan carries `Panel: none — docs-only change, no seat warranted` and every other stanza
- **THEN** the hook exits 0 with a `plan-shape gate:` nudge holding only the two reminders

#### Scenario: Settled panel, missing tasks
- **WHEN** the plan has a settled `Panel:` line but no `## Tasks` section
- **THEN** the hook exits 0 with a nudge naming `a ## Tasks section` as advisory

### Requirement: Plan-shape gate allows what it cannot judge
`session lint-plan-shape` MUST allow silently when the call carries an `agent_id`. When no plan text is obtainable, inline or from a contained read of the plan-store file, it MUST allow and SHALL record an `unjudged` row in `failopen.jsonl` with a static reason: `no-plan-text`, `plan-file-outside-store`, or `plan-store-file-unreadable`. An internal panic MUST allow.

#### Scenario: Plan file outside the plan store
- **WHEN** `planFilePath` names a file outside `<config_dir>/plans` and the payload carries no inline plan
- **THEN** the hook exits 0 and `failopen.jsonl` gains a row with reason `plan-file-outside-store`

### Requirement: Tick nudge after a landed commit
After a Bash `git commit` whose output shows git's commit summary line, `session nudge-plan-tick` SHALL nudge once per session per repo when the branch's in-flight plan (exact `branch:` match) was touched by neither the last three commits nor the working tree, naming it and mentioning `git commit --amend`. It MUST NOT block; an aborted commit, an unbound plan, or a git failure MUST allow.

#### Scenario: Three commits skip the plan
- **WHEN** a commit lands on `feat/x` whose in-flight plan was untouched by the last three commits and is clean in the working tree
- **THEN** the hook nudges `living plan untouched` naming the plan, and a later commit in the same session is silent

#### Scenario: Ordinary commit is allowed
- **WHEN** a commit lands on a branch with no in-flight plan
- **THEN** the hook exits 0 with no output

### Requirement: Ready-flip reconcile warning
On a Bash `gh pr ready` or `gh pr merge` aimed at this checkout's branch, `session warn-plan-ready-flip` SHALL nudge when its plan reads `status: in-flight` or has unticked checkboxes outside fences, naming the plan, status, and unticked count. It MUST NOT block. A flip aimed at another repo (`-R`, `--repo`, `GH_REPO=`, a PR URL) or branch MUST allow; a bare PR number counts as this branch.

#### Scenario: Flip with unticked boxes
- **WHEN** `gh pr ready 12` runs on a branch whose plan is `status: in-flight` with 3 unticked boxes
- **THEN** the hook nudges `ready-flip check:` naming the plan and `3 unticked checkbox(es)`

#### Scenario: Flip of another repo is allowed
- **WHEN** `gh pr merge 5 -R other-owner/other-repo` runs
- **THEN** the hook exits 0 with no output

### Requirement: Confirm a model switch away from the plan's driver
On PreModelSwitch, `session plan-driver` SHALL answer `ask` when the session's in-flight plan (matched by `approved_session_id`, else by `branch:`) records a `Driver:` family other than the target's. It MUST ask only when `CLAUDE_CODE_ENTRYPOINT=cli`, `CLAUDE_CODE_SESSION_ATTENDED=1`, `CLAUDE_CODE_REMOTE` is unset, and `source` is `command` or `picker`. Disagreeing or driverless plans and unknown families MUST allow. It MUST NOT block.

#### Scenario: Attended switch off the driver
- **WHEN** the session's plan says `Driver: opus` and the operator runs `/model` to a Sonnet model in the attended TUI
- **THEN** the hook answers `ask` with a reason naming both families and ending `Switch anyway?`

#### Scenario: Unattended switch
- **WHEN** the same switch arrives from `claude -p` with `CLAUDE_CODE_SESSION_ATTENDED=0`
- **THEN** the hook exits 0 with no output

#### Scenario: Plans disagree
- **WHEN** two in-flight plans on the current branch name different drivers and neither was approved by this session
- **THEN** the hook exits 0 with no output

### Requirement: In-flight plans surfaced at session start
`session start` SHALL add a fixed-size line when `docs/plans/` holds plans with frontmatter `status` `in-flight` or `blocked`, pointing at `cadence-hooks session plans`. Plans without a `status:` key MUST be skipped. The scan MUST be bounded to the newest files, skip symlinks, and say `At least` when cut. A second line SHALL name up to five in-flight plans that are uncommitted. Both MUST appear even when registration fails.

#### Scenario: Resuming into in-flight work
- **WHEN** a session starts in a repo with one in-flight plan in `docs/plans/`
- **THEN** the start nudge contains `1 in-flight plan in docs/plans/` and names `cadence-hooks session plans`

#### Scenario: Plan without a status key
- **WHEN** the only plan in `docs/plans/` has frontmatter with `date:` but no `status:`
- **THEN** no plan line appears

#### Scenario: Untracked plan
- **WHEN** an in-flight plan in `docs/plans/` is untracked
- **THEN** the start nudge contains `Uncommitted living plan(s):` naming it

### Requirement: Plans CLI action
`session plans` SHALL list every in-flight and blocked plan in the repo's `docs/plans/` with its next step, branch, and PR, with no cap on file count. It SHALL exit 0 for any complete answer, including none, and exit 2 outside a git repository or when an entry could not be listed or read, naming the root or each failed entry on stderr while printing what it found. It MUST work under `CADENCE_BYPASS=1`.

#### Scenario: Outside a repository
- **WHEN** `cadence-hooks session plans` runs outside a git repository
- **THEN** it exits 2 with `session plans: not inside a git repository.` and the scanned root on stderr

#### Scenario: No plans in flight
- **WHEN** `cadence-hooks session plans` runs in a repo with no in-flight or blocked plans
- **THEN** it exits 0

### Requirement: Untrusted plan text and cloud behavior
Values from plan files, their names, or the ledger MUST have control characters flattened and length capped before reaching additionalContext. Under `CLAUDE_CODE_REMOTE=true`, `persist-plan-approval` SHALL exit 0 with no output, which also stops its liveness refresh, while the four plan guards run. None of these hooks MAY be silenced through `.claude/cadence.json` `nudges`.

#### Scenario: Cloud approval
- **WHEN** a plan is approved in a session with `CLAUDE_CODE_REMOTE=true`
- **THEN** no plan file is written, while `session lint-plan-shape` still judged the plan at call time

#### Scenario: Crafted next step
- **WHEN** an in-flight plan's `next:` contains a control character followed by instruction text
- **THEN** `session plans` renders it on one line, truncated to the display cap
